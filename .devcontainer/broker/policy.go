package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
)

// Violation names the exact setting that failed validation.
type Violation struct {
	Service string
	Key     string
	Value   string
}

func (v Violation) String() string {
	return fmt.Sprintf("service=%q key=%q value=%q", v.Service, v.Key, v.Value)
}

const alloyImage = "grafana/alloy:v1.20.0@sha256:f111cce835516c5f99166342be7038496b52ced16667be5a11e19258a3e4cd30"

// Repo paths the daemon can see. Keep in sync with .devcontainer/docker-compose.yml.
var pinnedBinds = []string{
	".cloud/docker/alloy-config.alloy",
	".cloud/docker/certs/rabbitmq",
	".cloud/docker/config/pg_hba.conf",
	".cloud/docker/config/rabbitmq.conf",
	".cloud/docker/grafana/dashboards",
	".cloud/docker/grafana/provisioning",
	".cloud/docker/loki-config.yml",
	".cloud/docker/prometheus.yml",
	".cloud/env",
	"deployment/docker-entrypoint-initdb",
	"deployment/dump",
	"private",
	"scripts",
	"backend",
	"api",
	"api/.cloud/docker/pnpm-workspace.yaml",
	"frontend",
	"frontend/.cloud/docker/pnpm-workspace.yaml",
	"frontend/.cloud/docker/conf/caddy/Caddyfile",
	"frontend/.cloud/docker/conf/certs",
}

var buildContexts = []string{"api", "backend", "frontend"}

var alloyCommand = []any{
	"run",
	"/etc/alloy/config.alloy",
	"--server.http.listen-addr=0.0.0.0:12345",
	"--storage.path=/var/lib/alloy/data",
}

var alloyHostBinds = map[string]string{
	"/var/run/docker.sock":       "/var/run/docker.sock",
	"/var/lib/docker/containers": "/var/lib/docker/containers",
}

var (
	allowedTopLevel = set("name", "services", "networks", "volumes")
	allowedService  = set("build", "command", "container_name", "depends_on", "deploy",
		"entrypoint", "env_file", "environment", "extra_hosts", "healthcheck", "image",
		"networks", "platform", "ports", "restart", "shm_size", "volumes")
	allowedAlloy = set("command", "container_name", "depends_on", "deploy", "entrypoint",
		"image", "networks", "ports", "restart", "volumes")
	allowedBuild     = set("args", "context", "dockerfile", "target")
	allowedDeploy    = set("replicas", "resources")
	allowedResources = set("limits", "reservations")
	allowedLimit     = set("cpus", "memory")
	allowedNetwork   = set("name", "ipam")
	allowedVolume    = set("name", "external")
	allowedMount     = set("type", "source", "target", "read_only", "bind", "volume")
	allowedBindOpt   = set("create_host_path")
)

func set(keys ...string) map[string]bool {
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[k] = true
	}
	return out
}

// validate checks a resolved Compose config and returns everything it rejects.
func validate(raw []byte, repo string) ([]Violation, error) {
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("resolved config is not JSON: %w", err)
	}

	c := checker{repo: repo, binds: map[string]bool{}, contexts: map[string]bool{}}
	for _, rel := range pinnedBinds {
		c.binds[filepath.Join(repo, rel)] = true
	}
	for _, rel := range buildContexts {
		c.contexts[filepath.Join(repo, rel)] = true
	}

	c.unknownKeys("", "", cfg, allowedTopLevel)
	for name, raw := range asMap(cfg["services"]) {
		c.service(name, asMap(raw))
	}
	for name, raw := range asMap(cfg["networks"]) {
		c.unknownKeys("", "networks."+name, asMap(raw), allowedNetwork)
	}
	for name, raw := range asMap(cfg["volumes"]) {
		c.topVolume(name, asMap(raw))
	}
	return c.found, nil
}

type checker struct {
	repo     string
	binds    map[string]bool
	contexts map[string]bool
	found    []Violation
}

func (c *checker) reject(service, key string, value any) {
	c.found = append(c.found, Violation{service, key, fmt.Sprint(value)})
}

func (c *checker) unknownKeys(service, prefix string, m map[string]any, allowed map[string]bool) {
	for k, v := range m {
		if !allowed[k] {
			c.reject(service, strings.TrimPrefix(prefix+"."+k, "."), v)
		}
	}
}

func (c *checker) service(name string, s map[string]any) {
	isAlloy := name == "alloy"
	if isAlloy {
		c.unknownKeys(name, "", s, allowedAlloy)
		c.alloy(s)
	} else {
		c.unknownKeys(name, "", s, allowedService)
	}

	if build, ok := s["build"]; ok {
		c.build(name, build)
	}
	if deploy, ok := s["deploy"]; ok {
		c.deploy(name, asMap(deploy))
	}
	for _, raw := range asSlice(s["volumes"]) {
		c.mount(name, asMap(raw), isAlloy)
	}
}

func (c *checker) alloy(s map[string]any) {
	if s["image"] != alloyImage {
		c.reject("alloy", "image", s["image"])
	}
	if !reflect.DeepEqual(s["command"], alloyCommand) {
		c.reject("alloy", "command", s["command"])
	}
	if ep, ok := s["entrypoint"]; ok && ep != nil && len(asSlice(ep)) > 0 {
		c.reject("alloy", "entrypoint", ep)
	}
	if _, ok := s["build"]; ok {
		c.reject("alloy", "build", s["build"])
	}

	seen := map[string]bool{}
	for _, raw := range asSlice(s["volumes"]) {
		m := asMap(raw)
		if src, _ := m["source"].(string); m["type"] == "bind" {
			seen[src] = true
		}
	}
	want := []string{filepath.Join(c.repo, ".cloud/docker/alloy-config.alloy")}
	for src := range alloyHostBinds {
		want = append(want, src)
	}
	for _, src := range want {
		if !seen[src] {
			c.reject("alloy", "volumes", "missing "+src)
		}
	}
}

func (c *checker) build(service string, raw any) {
	b, ok := raw.(map[string]any)
	if !ok {
		c.reject(service, "build", raw)
		return
	}
	c.unknownKeys(service, "build", b, allowedBuild)

	ctx, _ := b["context"].(string)
	if !c.contexts[ctx] {
		c.reject(service, "build.context", ctx)
	} else if resolved, err := filepath.EvalSymlinks(ctx); err != nil || resolved != ctx {
		c.reject(service, "build.context", ctx+" is a symlink or missing")
	}
	if df, ok := b["dockerfile"].(string); ok {
		if filepath.IsAbs(df) || strings.Contains(df, "..") {
			c.reject(service, "build.dockerfile", df)
		}
	}
}

func (c *checker) deploy(service string, d map[string]any) {
	// Compose can add an empty placement when it resolves a file; any content is still rejected.
	if p, ok := d["placement"].(map[string]any); ok && len(p) == 0 {
		delete(d, "placement")
	}
	c.unknownKeys(service, "deploy", d, allowedDeploy)
	res := asMap(d["resources"])
	c.unknownKeys(service, "deploy.resources", res, allowedResources)
	for _, kind := range []string{"limits", "reservations"} {
		c.unknownKeys(service, "deploy.resources."+kind, asMap(res[kind]), allowedLimit)
	}
}

func (c *checker) mount(service string, m map[string]any, isAlloy bool) {
	c.unknownKeys(service, "volumes", m, allowedMount)
	switch m["type"] {
	case "volume":
	case "tmpfs":
	case "bind":
		c.unknownKeys(service, "volumes.bind", asMap(m["bind"]), allowedBindOpt)
		src, _ := m["source"].(string)
		if c.binds[src] {
			return
		}
		if isAlloy && alloyHostBinds[src] == src && src != "" {
			return
		}
		c.reject(service, "volumes.source", src)
	default:
		c.reject(service, "volumes.type", m["type"])
	}
}

func (c *checker) topVolume(name string, v map[string]any) {
	c.unknownKeys("", "volumes."+name, v, allowedVolume)
	if ext, ok := v["external"]; ok && ext != false && name != "pnpm-store" {
		c.reject("", "volumes."+name+".external", ext)
	}
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}
