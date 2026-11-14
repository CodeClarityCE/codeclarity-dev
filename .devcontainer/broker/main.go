// Broker runs a fixed set of Docker Compose commands for the agent, on its private daemon.
package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	log "github.com/sirupsen/logrus"
)

const (
	repoRoot     = "/workspaces/codeclarity-dev"
	dockerHost   = "unix:///run/dockerd/docker.sock"
	listenSocket = "/run/codeclarity-broker/broker.sock"
	resolvedPath = "/var/lib/broker/resolved.json"
	projectName  = "codeclarity-dev"
	exitMarker   = "__BROKER_EXIT__"
)

var composeFiles = []string{
	".cloud/docker/docker-compose.yaml",
	"api/.cloud/docker/docker-compose.yaml",
	"frontend/.cloud/docker/docker-compose.yaml",
	"backend/services/packageFollower/.cloud/docker/docker-compose.yaml",
	"backend/services/notifier/.cloud/docker/docker-compose.yaml",
	"backend/services/downloader/.cloud/docker/docker-compose.yaml",
	"backend/services/dispatcher/.cloud/docker/docker-compose.yaml",
	"backend/plugins/codeql/.cloud/docker/docker-compose.yaml",
	"backend/plugins/license-finder/.cloud/docker/docker-compose.yaml",
	"backend/plugins/js-patching/.cloud/docker/docker-compose.yaml",
	"backend/plugins/js-sbom/.cloud/docker/docker-compose.yaml",
	"backend/plugins/vuln-finder/.cloud/docker/docker-compose.yaml",
	"backend/plugins/php-sbom/.cloud/docker/docker-compose.yaml",
}

// Dump name and the database it restores into, for seed.
var restores = [][2]string{
	{"codeclarity", "codeclarity"},
	{"knowledge", "knowledge"},
	{"config", "config"},
	{"knowledge", "knowledge_test"},
	{"config", "config_test"},
	{"codeclarity", "codeclarity_test"},
}

// Databases with migrations, in the order they run.
var migrated = []string{"codeclarity", "knowledge", "plugins", "config"}

var serviceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

func validServiceName(name string) bool {
	return serviceName.MatchString(name)
}

type broker struct {
	mu sync.Mutex
}

// command describes one allowed operation.
type command struct {
	run         func(b *broker, w io.Writer, service string) int
	takes       bool
	needService bool
	// runWaived replaces run for a command that takes a gate waiver, given as environment.
	runWaived func(b *broker, w io.Writer, waiver []string) int
}

var commands = map[string]command{
	"up":               {run: (*broker).up, takes: true},
	"build":            {run: (*broker).build, takes: true},
	"restart":          {run: (*broker).restart, takes: true, needService: true},
	"logs":             {run: (*broker).logs, takes: true, needService: true},
	"pull":             {run: (*broker).pull},
	"down":             {run: (*broker).down},
	"ps":               {run: (*broker).ps},
	"seed":             {run: (*broker).seed},
	"reset":            {run: (*broker).reset},
	"migrate":          {run: (*broker).migrate, takes: true},
	"knowledge-osv":    {run: (*broker).knowledgeOSV},
	"knowledge-update": {run: (*broker).knowledgeUpdate},
	"dump-knowledge":   {runWaived: (*broker).dumpKnowledge},
}

func main() {
	log.SetFormatter(&log.JSONFormatter{})

	if err := os.MkdirAll(filepath.Dir(listenSocket), 0o755); err != nil {
		log.WithError(err).Fatal("cannot create socket directory")
	}
	_ = os.Remove(listenSocket)
	listener, err := net.Listen("unix", listenSocket)
	if err != nil {
		log.WithError(err).Fatal("cannot listen")
	}
	// Only the devcontainer shares this volume, and it runs as a non-root user.
	if err := os.Chmod(listenSocket, 0o666); err != nil {
		log.WithError(err).Fatal("cannot open socket permissions")
	}

	log.Info("broker ready")
	b := &broker{}
	if err := http.Serve(listener, http.HandlerFunc(b.handle)); err != nil {
		log.WithError(err).Fatal("server stopped")
	}
}

func (b *broker) handle(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	service := r.URL.Query().Get("service")
	entry := log.WithFields(log.Fields{"command": name, "service": service})

	cmd, ok := commands[name]
	if r.Method != http.MethodPost || !ok {
		entry.Warn("rejected unknown command")
		http.Error(w, "unknown command", http.StatusNotFound)
		return
	}
	if (service != "" && (!cmd.takes || !validServiceName(service))) || (cmd.needService && service == "") {
		entry.Warn("rejected bad service argument")
		http.Error(w, "bad service argument", http.StatusBadRequest)
		return
	}
	waive, reason := r.URL.Query().Get("waive"), r.URL.Query().Get("reason")
	if cmd.runWaived == nil && (waive != "" || reason != "") {
		entry.Warn("rejected a waiver on a command without a gate")
		http.Error(w, "this command takes no waiver", http.StatusBadRequest)
		return
	}
	waiver, err := gateWaiverEnv(waive, reason)
	if err != nil {
		entry.WithError(err).Warn("rejected bad waiver")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// One operation at a time.
	b.mu.Lock()
	defer b.mu.Unlock()

	out := &flushWriter{w: w}
	start := time.Now()
	var code int
	if cmd.runWaived != nil {
		code = cmd.runWaived(b, out, waiver)
	} else {
		code = cmd.run(b, out, service)
	}
	fmt.Fprintf(out, "%s %d\n", exitMarker, code)
	entry.WithFields(log.Fields{"exit": code, "seconds": int(time.Since(start).Seconds())}).Info("command finished")
}

// flushWriter streams output; once the client is gone it discards output so the command still finishes.
type flushWriter struct {
	w    http.ResponseWriter
	gone bool
}

func (f *flushWriter) Write(p []byte) (int, error) {
	if f.gone {
		return len(p), nil
	}
	if _, err := f.w.Write(p); err != nil {
		f.gone = true
		log.WithError(err).Warn("client left, discarding output")
		return len(p), nil
	}
	if flusher, ok := f.w.(http.Flusher); ok {
		flusher.Flush()
	}
	return len(p), nil
}

func docker(w io.Writer, args ...string) int {
	return dockerIO(w, nil, w, args...)
}

// dockerIO runs docker with its own stdin and stdout; stderr and broker errors go to w.
func dockerIO(w io.Writer, stdin io.Reader, stdout io.Writer, args ...string) int {
	return dockerEnv(w, nil, stdin, stdout, args...)
}

// dockerEnv is dockerIO with extra environment for the docker process, kept out of argv.
func dockerEnv(w io.Writer, env []string, stdin io.Reader, stdout io.Writer, args ...string) int {
	cmd := exec.Command("docker", args...)
	cmd.Env = append(append(os.Environ(), "DOCKER_HOST="+dockerHost), env...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = w
	if err := cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode()
		}
		fmt.Fprintf(w, "broker: cannot run docker: %v\n", err)
		return 1
	}
	return 0
}

// resolve renders the Compose files, validates the result and saves what passed.
func resolve(w io.Writer) bool {
	args := []string{"compose"}
	for _, f := range composeFiles {
		args = append(args, "-f", filepath.Join(repoRoot, f))
	}
	args = append(args, "config", "--format", "json")

	var stdout, stderr bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), "DOCKER_HOST="+dockerHost)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(w, "broker: compose config failed: %v\n%s", err, stderr.String())
		return false
	}

	found, err := validate(stdout.Bytes(), repoRoot)
	if err != nil {
		fmt.Fprintf(w, "broker: %v\n", err)
		return false
	}
	if len(found) > 0 {
		fmt.Fprintln(w, "broker: rejected, nothing was started:")
		for _, v := range found {
			fmt.Fprintf(w, "  %s\n", v)
			log.WithFields(log.Fields{"service": v.Service, "key": v.Key}).Warn("policy violation")
		}
		return false
	}
	if err := os.WriteFile(resolvedPath, stdout.Bytes(), 0o600); err != nil {
		fmt.Fprintf(w, "broker: cannot save resolved config: %v\n", err)
		return false
	}
	return true
}

func withService(args []string, service string) []string {
	if service != "" {
		return append(args, service)
	}
	return args
}

func resolved(args ...string) []string {
	return append([]string{"compose", "-f", resolvedPath}, args...)
}

func project(args ...string) []string {
	return append([]string{"compose", "-p", projectName}, args...)
}

func prepare(w io.Writer) bool {
	if err := ensureCerts(filepath.Join(repoRoot, ".cloud/docker/certs/rabbitmq")); err != nil {
		fmt.Fprintf(w, "broker: cannot create RabbitMQ certs: %v\n", err)
		return false
	}
	return docker(w, "volume", "create", "pnpm-store") == 0
}

func (b *broker) up(w io.Writer, service string) int {
	if !prepare(w) || !resolve(w) {
		return 1
	}
	return docker(w, withService(resolved("up", "-d"), service)...)
}

func (b *broker) build(w io.Writer, service string) int {
	if !resolve(w) {
		return 1
	}
	return docker(w, withService(resolved("build"), service)...)
}

func (b *broker) pull(w io.Writer, _ string) int {
	if !resolve(w) {
		return 1
	}
	return docker(w, resolved("pull")...)
}

func (b *broker) restart(w io.Writer, service string) int {
	if !resolve(w) {
		return 1
	}
	return docker(w, resolved("restart", service)...)
}

func (b *broker) down(w io.Writer, _ string) int {
	return docker(w, project("down")...)
}

func (b *broker) ps(w io.Writer, _ string) int {
	return docker(w, project("ps", "--all")...)
}

func (b *broker) logs(w io.Writer, service string) int {
	return docker(w, project("logs", "--no-color", "--tail", "500", service)...)
}

func waitForDB(w io.Writer) bool {
	for i := 0; i < 60; i++ {
		if docker(io.Discard, resolved("exec", "-T", "db", "pg_isready", "-U", "postgres")...) == 0 {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	fmt.Fprintln(w, "broker: database did not become ready")
	return false
}

// restoreDumpScript verifies and restores dumps; it runs inside the db container.
const restoreDumpScript = "deployment/scripts/restore-dump.sh"

// verifyDumpsArgs checks every dump against its manifest before anything is restored.
func verifyDumpsArgs(script string) []string {
	return []string{"exec", "-T", "db", "sh", "-c", script, "restore-dump", "verify"}
}

// restoreDumpArgs restores one dump, reassembling a split one, and creates the database if missing.
func restoreDumpArgs(script, dump, db string) []string {
	return []string{"exec", "-T", "db", "sh", "-c", script, "restore-dump", "restore", dump, db}
}

func (b *broker) seed(w io.Writer, _ string) int {
	script, err := os.ReadFile(filepath.Join(repoRoot, restoreDumpScript))
	if err != nil {
		fmt.Fprintf(w, "broker: cannot read the restore script: %v\n", err)
		return 1
	}
	if !resolve(w) || !waitForDB(w) {
		return 1
	}
	verify := func() int {
		return docker(w, resolved(verifyDumpsArgs(string(script))...)...)
	}
	restore := func(dump, db string) int {
		return docker(w, resolved(restoreDumpArgs(string(script), dump, db)...)...)
	}
	worst, verified := seedRestores(w, verify, restore)
	if !verified {
		return worst
	}
	// Dumps are older than the schema, so bring every database up to date.
	if code := b.runMigrations(w, migrated); code != 0 {
		worst = code
	}
	// Dumps also carry old advisories. Being offline should not fail the seed.
	fmt.Fprintln(w, "broker: refreshing OSV advisories")
	if code := docker(w, resolved(knowledgeOSVArgs()...)...); code != 0 {
		fmt.Fprintf(w, "broker: warning, OSV refresh exited %d; run make knowledge-update-osv later\n", code)
	}
	return worst
}

// seedRestores verifies the dumps, then restores each one; verified is false if nothing was restored.
func seedRestores(w io.Writer, verify func() int, restore func(dump, db string) int) (worst int, verified bool) {
	fmt.Fprintln(w, "broker: verifying the dumps against their manifest")
	if code := verify(); code != 0 {
		fmt.Fprintf(w, "broker: dump verification failed (exit %d), nothing was restored\n", code)
		return code, false
	}
	for _, r := range restores {
		dump, db := r[0], r[1]
		fmt.Fprintf(w, "broker: restoring %s into %s\n", dump, db)
		if code := restore(dump, db); code != 0 {
			fmt.Fprintf(w, "broker: restore of %s exited %d\n", db, code)
			worst = code
		}
	}
	return worst, true
}

// migrate applies pending migrations without touching existing data.
func (b *broker) migrate(w io.Writer, db string) int {
	targets, ok := migrationTargets(db)
	if !ok {
		fmt.Fprintf(w, "broker: unknown database %q, expected one of %s\n", db, strings.Join(migrated, ", "))
		return 1
	}
	if !resolve(w) || !waitForDB(w) {
		return 1
	}
	return b.runMigrations(w, targets)
}

// knowledgeOSV refreshes OSV advisories using the stack's own database settings.
func (b *broker) knowledgeOSV(w io.Writer, _ string) int {
	if !resolve(w) || !waitForDB(w) {
		return 1
	}
	return docker(w, resolved(knowledgeOSVArgs()...)...)
}

// knowledgeArgs runs a knowledge action, with extra env, in a Go service container that has the backend source.
func knowledgeArgs(env []string, action ...string) []string {
	args := []string{"exec", "-T", "-w", "/codeclarity/services/knowledge"}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	args = append(args, "service-package-follower", "go", "run", ".", "-knowledge", "-action")
	return append(args, action...)
}

// knowledgeOSVArgs runs the OSV update.
func knowledgeOSVArgs() []string {
	return knowledgeArgs(nil, "update-osv")
}

// knowledgeUpdate runs the full knowledge update, which needs the NVD key and takes hours.
func (b *broker) knowledgeUpdate(w io.Writer, _ string) int {
	ready := func() bool { return resolve(w) && waitForDB(w) }
	run := func(env, args []string) int { return dockerEnv(w, env, nil, w, resolved(args...)...) }
	return updateKnowledge(w, filepath.Join(repoRoot, secretsFile), ready, run)
}

// secretsFile holds developer secrets; it is gitignored and read only when a command needs it.
const secretsFile = ".cloud/env/.env.secrets"

// updateKnowledge runs the full knowledge update with the NVD key from path, passed only in docker's environment.
func updateKnowledge(w io.Writer, path string, ready func() bool, run func(env, args []string) int) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(w, "broker: cannot read %s; copy %s.example and set NVD_API_KEY\n", secretsFile, secretsFile)
		return 1
	}
	key := envValue(raw, "NVD_API_KEY")
	if key == "" || key == "!ChangeMe!" {
		fmt.Fprintf(w, "broker: NVD_API_KEY is not set in %s\n", secretsFile)
		return 1
	}
	if !ready() {
		return 1
	}
	return run([]string{"NVD_API_KEY=" + key}, knowledgeUpdateArgs())
}

// knowledgeUpdateArgs runs the full update; -e names the key so its value stays out of argv.
func knowledgeUpdateArgs() []string {
	return knowledgeArgs([]string{"NVD_API_KEY"}, "update")
}

// envValue returns name's value from env file content, without surrounding quotes.
func envValue(raw []byte, name string) string {
	value := ""
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(k) == name {
			v = strings.TrimSpace(v)
			if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
				v = v[1 : len(v)-1]
			}
			value = v
		}
	}
	return value
}

// dumpKnowledgeScript dumps knowledge and config with a manifest; it runs inside the db container.
const dumpKnowledgeScript = ".cloud/scripts/dump-knowledge-in-db.sh"

// dumpKnowledge dumps knowledge and config only when the completeness gate passes,
// with any waived checks recorded in the gate report.
func (b *broker) dumpKnowledge(w io.Writer, waiver []string) int {
	script, err := os.ReadFile(filepath.Join(repoRoot, dumpKnowledgeScript))
	if err != nil {
		fmt.Fprintf(w, "broker: cannot read the dump script: %v\n", err)
		return 1
	}
	if !resolve(w) || !waitForDB(w) {
		return 1
	}
	env, err := expectedMigrationsEnv(filepath.Join(repoRoot, apiMigrationsDir))
	if err != nil {
		fmt.Fprintf(w, "broker: warning, the gate falls back to its own migration list: %v\n", err)
	}
	env = append(env, waiver...)
	gate := func(stdout io.Writer) int {
		return dockerIO(w, nil, stdout, resolved(knowledgeGateArgs(env)...)...)
	}
	dump := func(stdin io.Reader) int {
		return dockerIO(w, stdin, w, resolved(dumpKnowledgeArgs(string(script))...)...)
	}
	return gatedDump(w, gate, dump)
}

// gatedDump runs the gate, shows its report, and hands the report to the dump only if it passed.
func gatedDump(w io.Writer, gate func(stdout io.Writer) int, dump func(stdin io.Reader) int) int {
	fmt.Fprintln(w, "broker: running the knowledge completeness gate")
	var report bytes.Buffer
	code := gate(&report)
	_, _ = w.Write(report.Bytes())
	if code != 0 {
		fmt.Fprintf(w, "broker: the completeness gate failed (exit %d), nothing was dumped\n", code)
		return code
	}
	return dump(&report)
}

// waivedChecks is a comma-separated list of <source>.<check> or <source>.* gate check patterns.
var waivedChecks = regexp.MustCompile(`^[a-z_]+\.([a-z_]+|\*)(,[a-z_]+\.([a-z_]+|\*))*$`)

// maxWaiverReason bounds the reason recorded in the gate report.
const maxWaiverReason = 300

// gateWaiverEnv checks a waiver from make's WAIVE and REASON and returns it as the gate's environment.
// The gate itself refuses checks that cannot be waived.
func gateWaiverEnv(waive, reason string) ([]string, error) {
	if waive == "" && reason == "" {
		return nil, nil
	}
	if !waivedChecks.MatchString(waive) {
		return nil, fmt.Errorf("WAIVE must list <source>.<check> or <source>.* patterns, got %q", waive)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > maxWaiverReason || strings.IndexFunc(reason, unicode.IsControl) >= 0 {
		return nil, fmt.Errorf("REASON must be one line of at most %d characters", maxWaiverReason)
	}
	return []string{"KNOWLEDGE_GATE_WAIVE=" + waive, "KNOWLEDGE_GATE_WAIVE_REASON=" + reason}, nil
}

// knowledgeGateArgs runs the read-only completeness gate; its JSON report is on stdout.
func knowledgeGateArgs(env []string) []string {
	return knowledgeArgs(env, "validate", "-read-only")
}

// apiMigrationsDir holds the API's TypeORM migrations, one folder per database.
const apiMigrationsDir = "api/src/migrations"

var migrationClass = regexp.MustCompile(`export class (\w+)`)

// expectedMigrationsEnv tells the gate to expect the knowledge and config migrations in dir.
func expectedMigrationsEnv(dir string) ([]string, error) {
	var env []string
	for _, db := range []string{"knowledge", "config"} {
		files, err := filepath.Glob(filepath.Join(dir, db, "*.ts"))
		if err != nil {
			return nil, err
		}
		// File names start with the timestamp, so sorting puts them oldest first.
		slices.Sort(files)
		var names []string
		for _, file := range files {
			source, err := os.ReadFile(file)
			if err != nil {
				return nil, err
			}
			if match := migrationClass.FindSubmatch(source); match != nil {
				names = append(names, string(match[1]))
			}
		}
		if len(names) == 0 {
			return nil, fmt.Errorf("no %s migrations in %s", db, dir)
		}
		env = append(env, "KNOWLEDGE_EXPECTED_MIGRATIONS_"+strings.ToUpper(db)+"="+strings.Join(names, ","))
	}
	return env, nil
}

// dumpKnowledgeArgs runs the dump script in the db container, which writes to deployment/dump.
func dumpKnowledgeArgs(script string) []string {
	return []string{"exec", "-T", "db", "sh", "-c", script, "dump-knowledge"}
}

// migrationTargets returns the databases to migrate; no name means all of them.
func migrationTargets(db string) ([]string, bool) {
	if db == "" {
		return migrated, true
	}
	if slices.Contains(migrated, db) {
		return []string{db}, true
	}
	return nil, false
}

// runMigrations tries every database and returns the last failure.
func (b *broker) runMigrations(w io.Writer, dbs []string) int {
	worst := 0
	for _, db := range dbs {
		fmt.Fprintf(w, "broker: migrating %s\n", db)
		if code := docker(w, resolved(migrateArgs(db)...)...); code != 0 {
			fmt.Fprintf(w, "broker: migration of %s exited %d\n", db, code)
			worst = code
		}
	}
	return worst
}

// migrateArgs runs one database's migrations in the api container, straight on Postgres.
func migrateArgs(db string) []string {
	return []string{"exec", "-T", "-e", "PG_DB_HOST=db", "-e", "PG_DB_PORT=5432", "api", "pnpm", "migration:run:" + db}
}

func (b *broker) reset(w io.Writer, service string) int {
	if code := docker(w, project("down", "-v")...); code != 0 {
		return code
	}
	if code := b.up(w, ""); code != 0 {
		return code
	}
	return b.seed(w, service)
}
