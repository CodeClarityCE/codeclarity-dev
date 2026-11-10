package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// goodConfig returns a valid resolved config rooted at a temp repo.
func goodConfig(t *testing.T) (map[string]any, string) {
	t.Helper()
	repo := t.TempDir()
	repo, _ = filepath.EvalSymlinks(repo)
	for _, dir := range buildContexts {
		if err := os.MkdirAll(filepath.Join(repo, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := map[string]any{
		"name": "codeclarity-dev",
		"services": map[string]any{
			"api": map[string]any{
				"image":       "codeclarityce/api-dev:latest",
				"environment": map[string]any{"A": "b"},
				"extra_hosts": []any{"host.docker.internal=host-gateway"},
				"build": map[string]any{
					"context": filepath.Join(repo, "api"), "dockerfile": ".cloud/docker/Dockerfile",
					"target": "dev", "args": map[string]any{"X": "y"},
				},
				"deploy": map[string]any{
					"replicas":  float64(4),
					"resources": map[string]any{"limits": map[string]any{"cpus": "1", "memory": "1G"}},
				},
				"volumes": []any{
					map[string]any{"type": "bind", "source": filepath.Join(repo, "api"), "target": "/app", "bind": map[string]any{"create_host_path": true}},
					map[string]any{"type": "volume", "target": "/app/node_modules", "volume": map[string]any{}},
				},
			},
			"alloy": alloyService(repo),
		},
		"networks": map[string]any{"default": map[string]any{"name": "codeclarity-dev_default", "ipam": map[string]any{}}},
		"volumes":  map[string]any{"pnpm-store": map[string]any{"name": "pnpm-store", "external": true}, "db": map[string]any{"name": "db"}},
	}
	return cfg, repo
}

func alloyService(repo string) map[string]any {
	return map[string]any{
		"image":   alloyImage,
		"command": alloyCommand,
		"volumes": []any{
			map[string]any{"type": "bind", "source": filepath.Join(repo, ".cloud/docker/alloy-config.alloy"), "target": "/etc/alloy/config.alloy", "read_only": true},
			map[string]any{"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock", "read_only": true},
			map[string]any{"type": "bind", "source": "/var/lib/docker/containers", "target": "/var/lib/docker/containers", "read_only": true},
		},
	}
}

func run(t *testing.T, cfg map[string]any, repo string) []Violation {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	found, err := validate(raw, repo)
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func svc(cfg map[string]any, name string) map[string]any {
	return cfg["services"].(map[string]any)[name].(map[string]any)
}

func TestAcceptsCurrentShape(t *testing.T) {
	cfg, repo := goodConfig(t)
	if found := run(t, cfg, repo); len(found) != 0 {
		t.Fatalf("expected no violations, got %v", found)
	}
}

func TestAcceptsEmptyPlacement(t *testing.T) {
	cfg, repo := goodConfig(t)
	svc(cfg, "api")["deploy"].(map[string]any)["placement"] = map[string]any{}
	if found := run(t, cfg, repo); len(found) != 0 {
		t.Fatalf("expected no violations, got %v", found)
	}
}

func TestRejects(t *testing.T) {
	bind := func(src string) map[string]any {
		return map[string]any{"type": "bind", "source": src, "target": "/x"}
	}
	cases := []struct {
		name string
		key  string
		mut  func(cfg map[string]any, repo string)
	}{
		{"privileged", "privileged", func(c map[string]any, _ string) { svc(c, "api")["privileged"] = true }},
		{"cap_add", "cap_add", func(c map[string]any, _ string) { svc(c, "api")["cap_add"] = []any{"SYS_ADMIN"} }},
		{"security_opt", "security_opt", func(c map[string]any, _ string) { svc(c, "api")["security_opt"] = []any{"seccomp=unconfined"} }},
		{"pid host", "pid", func(c map[string]any, _ string) { svc(c, "api")["pid"] = "host" }},
		{"network host", "network_mode", func(c map[string]any, _ string) { svc(c, "api")["network_mode"] = "host" }},
		{"devices", "devices", func(c map[string]any, _ string) { svc(c, "api")["devices"] = []any{"/dev/kmsg"} }},
		{"volumes_from", "volumes_from", func(c map[string]any, _ string) { svc(c, "api")["volumes_from"] = []any{"alloy"} }},
		{"unknown future key", "new_escape_hatch", func(c map[string]any, _ string) { svc(c, "api")["new_escape_hatch"] = true }},
		{"unknown top-level", "secrets", func(c map[string]any, _ string) { c["secrets"] = map[string]any{} }},
		{"root bind", "volumes.source", func(c map[string]any, _ string) {
			svc(c, "api")["volumes"] = []any{bind("/")}
		}},
		{"socket on non-alloy", "volumes.source", func(c map[string]any, _ string) {
			svc(c, "api")["volumes"] = []any{bind("/var/run/docker.sock")}
		}},
		{"unpinned repo subpath", "volumes.source", func(c map[string]any, r string) {
			svc(c, "api")["volumes"] = []any{bind(filepath.Join(r, "api/src"))}
		}},
		{"dotdot escape", "volumes.source", func(c map[string]any, r string) {
			svc(c, "api")["volumes"] = []any{bind(r + "/api/../../etc")}
		}},
		{"bind propagation", "volumes.bind.propagation", func(c map[string]any, r string) {
			svc(c, "api")["volumes"] = []any{map[string]any{"type": "bind", "source": filepath.Join(r, "api"), "target": "/x", "bind": map[string]any{"propagation": "rshared"}}}
		}},
		{"npipe mount", "volumes.type", func(c map[string]any, _ string) {
			svc(c, "api")["volumes"] = []any{map[string]any{"type": "npipe", "target": "/x"}}
		}},
		{"volume driver_opts", "volumes.db.driver_opts", func(c map[string]any, _ string) {
			c["volumes"].(map[string]any)["db"] = map[string]any{"driver_opts": map[string]any{"device": "/", "o": "bind"}}
		}},
		{"other external volume", "volumes.db.external", func(c map[string]any, _ string) {
			c["volumes"].(map[string]any)["db"] = map[string]any{"external": true}
		}},
		{"network driver", "networks.default.driver", func(c map[string]any, _ string) {
			c["networks"].(map[string]any)["default"] = map[string]any{"driver": "macvlan"}
		}},
		{"build network", "build.network", func(c map[string]any, _ string) { svc(c, "api")["build"].(map[string]any)["network"] = "host" }},
		{"build entitlements", "build.entitlements", func(c map[string]any, _ string) {
			svc(c, "api")["build"].(map[string]any)["entitlements"] = []any{"security.insecure"}
		}},
		{"build privileged", "build.privileged", func(c map[string]any, _ string) { svc(c, "api")["build"].(map[string]any)["privileged"] = true }},
		{"build secrets", "build.secrets", func(c map[string]any, _ string) { svc(c, "api")["build"].(map[string]any)["secrets"] = []any{} }},
		{"additional contexts", "build.additional_contexts", func(c map[string]any, _ string) {
			svc(c, "api")["build"].(map[string]any)["additional_contexts"] = map[string]any{}
		}},
		{"remote context", "build.context", func(c map[string]any, _ string) {
			svc(c, "api")["build"].(map[string]any)["context"] = "https://example.com/x.git"
		}},
		{"context outside repo", "build.context", func(c map[string]any, _ string) { svc(c, "api")["build"].(map[string]any)["context"] = "/" }},
		{"dockerfile escape", "build.dockerfile", func(c map[string]any, _ string) { svc(c, "api")["build"].(map[string]any)["dockerfile"] = "../../x" }},
		{"device reservation", "deploy.resources.reservations.devices", func(c map[string]any, _ string) {
			svc(c, "api")["deploy"].(map[string]any)["resources"] = map[string]any{"reservations": map[string]any{"devices": []any{}}}
		}},
		{"placement constraints", "deploy.placement", func(c map[string]any, _ string) {
			svc(c, "api")["deploy"].(map[string]any)["placement"] = map[string]any{"constraints": []any{"node.role==manager"}}
		}},
		{"placement not a map", "deploy.placement", func(c map[string]any, _ string) {
			svc(c, "api")["deploy"].(map[string]any)["placement"] = "anything"
		}},
		{"alloy image swap", "image", func(c map[string]any, _ string) { svc(c, "alloy")["image"] = "evil:latest" }},
		{"alloy command swap", "command", func(c map[string]any, _ string) { svc(c, "alloy")["command"] = []any{"sh"} }},
		{"alloy entrypoint", "entrypoint", func(c map[string]any, _ string) { svc(c, "alloy")["entrypoint"] = []any{"/bin/sh"} }},
		{"alloy environment", "environment", func(c map[string]any, _ string) {
			svc(c, "alloy")["environment"] = map[string]any{"LD_PRELOAD": "/etc/alloy/config.alloy"}
		}},
		{"alloy extra bind", "volumes.source", func(c map[string]any, _ string) {
			s := svc(c, "alloy")
			s["volumes"] = append(s["volumes"].([]any), bind("/"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, repo := goodConfig(t)
			tc.mut(cfg, repo)
			found := run(t, cfg, repo)
			for _, v := range found {
				if v.Key == tc.key {
					return
				}
			}
			t.Fatalf("expected a violation on %q, got %v", tc.key, found)
		})
	}
}

func TestRejectsSymlinkedContext(t *testing.T) {
	cfg, repo := goodConfig(t)
	api := filepath.Join(repo, "api")
	if err := os.Remove(api); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", api); err != nil {
		t.Fatal(err)
	}
	found := run(t, cfg, repo)
	for _, v := range found {
		if v.Key == "build.context" {
			return
		}
	}
	t.Fatalf("expected a build.context violation, got %v", found)
}

func TestRejectsBadJSON(t *testing.T) {
	if _, err := validate([]byte("not json"), "/repo"); err == nil {
		t.Fatal("expected an error")
	}
}

// The daemon's mounts and the policy must list the same paths.
func TestPinnedBindsMatchComposeFile(t *testing.T) {
	raw, err := os.ReadFile("../docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range pinnedBinds {
		want := "- ../" + rel + ":/workspaces/codeclarity-dev/" + rel + "\n"
		if !strings.Contains(string(raw), want) {
			t.Errorf("docker-compose.yml is missing %q", want)
		}
	}
}

func TestAlloyMatchesStackCompose(t *testing.T) {
	raw, err := os.ReadFile("../../.cloud/docker/docker-compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), alloyImage) {
		t.Errorf("stack compose does not use %s", alloyImage)
	}
}

func TestRestoreDumpRunsTheScriptInTheDBContainer(t *testing.T) {
	got := restoreDumpArgs("echo restoring", "knowledge", "knowledge_test")
	want := []string{"exec", "-T", "db", "sh", "-c", "echo restoring", "restore-dump", "restore", "knowledge", "knowledge_test"}
	if !slices.Equal(got, want) {
		t.Errorf("restoreDumpArgs = %q, want %q", got, want)
	}
	got = verifyDumpsArgs("echo verifying")
	want = []string{"exec", "-T", "db", "sh", "-c", "echo verifying", "restore-dump", "verify"}
	if !slices.Equal(got, want) {
		t.Errorf("verifyDumpsArgs = %q, want %q", got, want)
	}
}

func TestRestoreDumpScriptIsInTheDeploymentRepo(t *testing.T) {
	if _, err := os.Stat("../../deployment/scripts"); err != nil {
		t.Skip("the deployment submodule is not checked out")
	}
	if _, err := os.Stat(filepath.Join("../..", restoreDumpScript)); err != nil {
		t.Errorf("broker reads %s: %v", restoreDumpScript, err)
	}
}

func TestSeedRestoresNothingWhenVerificationFails(t *testing.T) {
	var out bytes.Buffer
	var restored []string
	verify := func() int { return 1 }
	restore := func(dump, db string) int {
		restored = append(restored, db)
		return 0
	}
	code, ok := seedRestores(&out, verify, restore)
	if code == 0 || ok {
		t.Errorf("a failed verification should fail the seed, got %d, %v", code, ok)
	}
	if len(restored) > 0 {
		t.Errorf("nothing should be restored, got %v", restored)
	}
	if !strings.Contains(out.String(), "nothing was restored") {
		t.Errorf("the seed should say nothing was restored, got %q", out.String())
	}
}

func TestSeedRestoresEveryDumpOnceVerified(t *testing.T) {
	var out bytes.Buffer
	var restored [][2]string
	verify := func() int { return 0 }
	restore := func(dump, db string) int {
		restored = append(restored, [2]string{dump, db})
		if db == "config" {
			return 4
		}
		return 0
	}
	code, ok := seedRestores(&out, verify, restore)
	if code != 4 || !ok {
		t.Errorf("a failed restore should give its exit code, got %d, %v", code, ok)
	}
	if !slices.Equal(restored, restores) {
		t.Errorf("restored %v, want %v", restored, restores)
	}
}

func TestMigrateArgsRunInTheAPIContainer(t *testing.T) {
	got := strings.Join(migrateArgs("plugins"), " ")
	want := "exec -T -e PG_DB_HOST=db -e PG_DB_PORT=5432 api pnpm migration:run:plugins"
	if got != want {
		t.Errorf("migrateArgs = %q, want %q", got, want)
	}
}

func TestMigrationTargets(t *testing.T) {
	if got, ok := migrationTargets(""); !ok || !slices.Equal(got, migrated) {
		t.Errorf("no name should select every database, got %v, %v", got, ok)
	}
	if got, ok := migrationTargets("config"); !ok || !slices.Equal(got, []string{"config"}) {
		t.Errorf("config should select only itself, got %v, %v", got, ok)
	}
	if _, ok := migrationTargets("api"); ok {
		t.Error("a name without migrations should be rejected")
	}
}

func TestKnowledgeOSVRunsInTheBackendContainer(t *testing.T) {
	got := strings.Join(knowledgeOSVArgs(), " ")
	want := "exec -T -w /codeclarity/services/knowledge service-package-follower go run . -knowledge -action update-osv"
	if got != want {
		t.Errorf("knowledgeOSVArgs = %q, want %q", got, want)
	}
}

func TestServiceNames(t *testing.T) {
	for name, want := range map[string]bool{"api": true, "js-sbom": true, "": false, "-v": false, "a b": false, "../x": false} {
		if got := validServiceName(name); got != want {
			t.Errorf("validServiceName(%q) = %v", name, got)
		}
	}
}

func TestParseCertBundle(t *testing.T) {
	dir := t.TempDir()
	if err := ensureCerts(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v", info.Mode().Perm())
	}
	before, _ := os.ReadFile(filepath.Join(dir, "server.crt"))
	if err := ensureCerts(dir); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "server.crt"))
	if string(before) != string(after) {
		t.Error("existing certs were regenerated")
	}
}

func TestDumpKnowledgeGateRunsReadOnlyInTheBackendContainer(t *testing.T) {
	got := strings.Join(knowledgeGateArgs([]string{"A=1", "B=2"}), " ")
	want := "exec -T -w /codeclarity/services/knowledge -e A=1 -e B=2 service-package-follower go run . -knowledge -action validate -read-only"
	if got != want {
		t.Errorf("knowledgeGateArgs = %q, want %q", got, want)
	}
}

// writeMigration writes one TypeORM migration file declaring class.
func writeMigration(t *testing.T, dir, folder, file, class string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, folder), 0o755); err != nil {
		t.Fatal(err)
	}
	source := "import { MigrationInterface } from \"typeorm\";\n\nexport class " + class + " implements MigrationInterface {}\n"
	if err := os.WriteFile(filepath.Join(dir, folder, file), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDumpKnowledgeGateExpectsTheAPIMigrations(t *testing.T) {
	dir := t.TempDir()
	writeMigration(t, dir, "knowledge", "1794528000000-AddUpstreamTotal.ts", "AddUpstreamTotal1794528000000")
	writeMigration(t, dir, "knowledge", "1754600000000-CreateKnowledgeBaseline.ts", "CreateKnowledgeBaseline1754600000000")
	writeMigration(t, dir, "config", "1754600000000-CreateConfigBaseline.ts", "CreateConfigBaseline1754600000000")
	got, err := expectedMigrationsEnv(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"KNOWLEDGE_EXPECTED_MIGRATIONS_KNOWLEDGE=CreateKnowledgeBaseline1754600000000,AddUpstreamTotal1794528000000",
		"KNOWLEDGE_EXPECTED_MIGRATIONS_CONFIG=CreateConfigBaseline1754600000000",
	}
	if !slices.Equal(got, want) {
		t.Errorf("expectedMigrationsEnv = %q, want %q", got, want)
	}
}

func TestDumpKnowledgeGateNeedsAPIMigrations(t *testing.T) {
	dir := t.TempDir()
	writeMigration(t, dir, "knowledge", "1754600000000-CreateKnowledgeBaseline.ts", "CreateKnowledgeBaseline1754600000000")
	if _, err := expectedMigrationsEnv(dir); err == nil {
		t.Error("a missing config migrations folder should be an error")
	}
}

func TestTheBrokerReadsTheRepoAPIMigrations(t *testing.T) {
	if _, err := os.Stat("../../api/package.json"); err != nil {
		t.Skip("the api submodule is not checked out")
	}
	if _, err := expectedMigrationsEnv(filepath.Join("../..", apiMigrationsDir)); err != nil {
		t.Errorf("broker reads %s: %v", apiMigrationsDir, err)
	}
}

func TestDumpKnowledgeRunsTheScriptInTheDBContainer(t *testing.T) {
	got := dumpKnowledgeArgs("echo dumping")
	want := []string{"exec", "-T", "db", "sh", "-c", "echo dumping", "dump-knowledge"}
	if !slices.Equal(got, want) {
		t.Errorf("dumpKnowledgeArgs = %q, want %q", got, want)
	}
}

func TestDumpKnowledgeScriptIsInTheRepo(t *testing.T) {
	if _, err := os.Stat(filepath.Join("../..", dumpKnowledgeScript)); err != nil {
		t.Errorf("broker reads %s: %v", dumpKnowledgeScript, err)
	}
}

func TestDumpKnowledgeTakesNoArgument(t *testing.T) {
	cmd, ok := commands["dump-knowledge"]
	if !ok || cmd.takes {
		t.Errorf("dump-knowledge should be a command without an argument, got %+v, %v", cmd, ok)
	}
}

func TestDumpKnowledgeStopsWhenTheGateFails(t *testing.T) {
	var out bytes.Buffer
	dumped := false
	gate := func(stdout io.Writer) int {
		fmt.Fprintln(stdout, `{"passed": false}`)
		return 1
	}
	dump := func(io.Reader) int {
		dumped = true
		return 0
	}
	if code := gatedDump(&out, gate, dump); code == 0 {
		t.Error("a failed gate should fail the command")
	}
	if dumped {
		t.Error("a failed gate must not dump")
	}
	if !strings.Contains(out.String(), `{"passed": false}`) {
		t.Errorf("the gate report should be shown, got %q", out.String())
	}
}

func TestDumpKnowledgeHandsThePassingReportToTheDump(t *testing.T) {
	var out bytes.Buffer
	var got string
	gate := func(stdout io.Writer) int {
		fmt.Fprintln(stdout, `{"passed": true}`)
		return 0
	}
	dump := func(stdin io.Reader) int {
		raw, _ := io.ReadAll(stdin)
		got = string(raw)
		return 3
	}
	if code := gatedDump(&out, gate, dump); code != 3 {
		t.Errorf("the command should exit with the dump's status, got %d", code)
	}
	if got != "{\"passed\": true}\n" {
		t.Errorf("dump read %q from stdin", got)
	}
}
