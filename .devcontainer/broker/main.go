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
	"strings"
	"sync"
	"time"

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
}

var commands = map[string]command{
	"up":      {run: (*broker).up, takes: true},
	"build":   {run: (*broker).build, takes: true},
	"restart": {run: (*broker).restart, takes: true, needService: true},
	"logs":    {run: (*broker).logs, takes: true, needService: true},
	"pull":    {run: (*broker).pull},
	"down":    {run: (*broker).down},
	"ps":      {run: (*broker).ps},
	"seed":    {run: (*broker).seed},
	"reset":   {run: (*broker).reset},
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

	// One operation at a time.
	b.mu.Lock()
	defer b.mu.Unlock()

	out := &flushWriter{w: w}
	start := time.Now()
	code := cmd.run(b, out, service)
	fmt.Fprintf(out, "%s %d\n", exitMarker, code)
	entry.WithFields(log.Fields{"exit": code, "seconds": int(time.Since(start).Seconds())}).Info("command finished")
}

type flushWriter struct {
	w http.ResponseWriter
}

func (f *flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if flusher, ok := f.w.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
}

func docker(w io.Writer, args ...string) int {
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), "DOCKER_HOST="+dockerHost)
	cmd.Stdout = w
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

// restoreScript creates the database if it is missing, then restores the dump into it.
func restoreScript(dump, db string) string {
	return fmt.Sprintf(
		`export PGPASSWORD=$POSTGRES_PASSWORD; { psql -w -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname='%[2]s'" | grep -q 1 || createdb -w -U postgres %[2]s; } && pg_restore -l /dump/%[1]s.dump > /dump/%[1]s.list && pg_restore -w -U postgres -d %[2]s -L /dump/%[1]s.list /dump/%[1]s.dump`,
		dump, db)
}

func (b *broker) seed(w io.Writer, _ string) int {
	if !resolve(w) || !waitForDB(w) {
		return 1
	}
	worst := 0
	for _, r := range restores {
		dump, db := r[0], r[1]
		fmt.Fprintf(w, "broker: restoring %s into %s\n", dump, db)
		if code := docker(w, resolved("exec", "-T", "db", "sh", "-c", restoreScript(dump, db))...); code != 0 {
			fmt.Fprintf(w, "broker: restore of %s exited %d\n", db, code)
			worst = code
		}
	}
	return worst
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
