package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestRestoreScriptCreatesMissingDatabase(t *testing.T) {
	got := restoreScript("knowledge", "knowledge_test")
	for _, want := range []string{"createdb -w -U postgres knowledge_test", "-d knowledge_test", "/dump/knowledge.dump"} {
		if !strings.Contains(got, want) {
			t.Errorf("restore script is missing %q: %s", want, got)
		}
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
