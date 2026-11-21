package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunInPTYGivesTheCommandATerminalOfTheClientSize(t *testing.T) {
	var out bytes.Buffer
	cmd := exec.Command("sh", "-c", "test -t 0 && test -t 1 && test -t 2 && stty size")
	if code := runInPTY(cmd, &out, termSize{rows: 40, cols: 120}); code != 0 {
		t.Fatalf("exit %d, output %q", code, out.String())
	}
	if got := strings.TrimSpace(out.String()); got != "40 120" {
		t.Fatalf("stty size = %q, want 40 120", got)
	}
}

func TestRunInPTYKeepsTheExitCode(t *testing.T) {
	if code := runInPTY(exec.Command("sh", "-c", "exit 3"), &bytes.Buffer{}, termSize{rows: 24, cols: 80}); code != 3 {
		t.Fatalf("exit %d, want 3", code)
	}
}

func TestRunInPTYKeepsOutputWithoutATrailingNewline(t *testing.T) {
	var out bytes.Buffer
	runInPTY(exec.Command("printf", "one\ntwo"), &out, termSize{rows: 24, cols: 80})
	if got := out.String(); got != "one\r\ntwo" {
		t.Fatalf("output %q, want %q", got, "one\r\ntwo")
	}
}

func TestRunInPTYStopsWaitingForALeftoverProcess(t *testing.T) {
	// The background sleep ignores the hangup and keeps the terminal open after sh exits.
	cmd := exec.Command("sh", "-c", "trap '' HUP; sleep 30 & echo done")
	var out bytes.Buffer
	if code := runInPTY(cmd, &out, termSize{rows: 24, cols: 80}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "done") {
		t.Fatalf("output %q", out.String())
	}
}

func TestTerminalSizeIsOnlyTakenWithTTY(t *testing.T) {
	for _, query := range []string{
		"tty=2&rows=24&cols=80",
		"tty=1",
		"tty=1&rows=24",
		"tty=1&rows=0&cols=80",
		"tty=1&rows=24&cols=abc",
		"tty=1&rows=24&cols=1001",
		"rows=24&cols=80",
	} {
		rec := httptest.NewRecorder()
		(&broker{}).handle(rec, httptest.NewRequest(http.MethodPost, "/ps?"+query, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", query, rec.Code)
		}
	}
}

func TestTerminalSizeFromAValidQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/ps?tty=1&rows=50&cols=200", nil)
	size, err := termSizeFrom(req.URL.Query())
	if err != nil || size == nil || *size != (termSize{rows: 50, cols: 200}) {
		t.Fatalf("got %v, %v", size, err)
	}
}

func TestOnlyTerminalClientsGetTheTerminal(t *testing.T) {
	if terminal(&flushWriter{}) != nil || terminal(&bytes.Buffer{}) != nil {
		t.Fatal("plain writers must not get a terminal")
	}
	if terminal(&flushWriter{term: &termSize{rows: 1, cols: 1}}) == nil {
		t.Fatal("a terminal client must get a terminal")
	}
}

func TestLogsAreColouredOnlyOnATerminal(t *testing.T) {
	if got := strings.Join(logsArgs(false, "api"), " "); got != "logs --no-color --tail 500 api" {
		t.Fatalf("plain: %s", got)
	}
	if got := strings.Join(logsArgs(true, "api"), " "); got != "logs --tail 500 api" {
		t.Fatalf("terminal: %s", got)
	}
}

func TestExitMarkerStartsALine(t *testing.T) {
	for _, tc := range []struct{ output, want string }{
		{"", "__BROKER_EXIT__ 0\n"},
		{"done\n", "done\n__BROKER_EXIT__ 0\n"},
		{"50%\r", "50%\r\n__BROKER_EXIT__ 0\n"},
	} {
		rec := httptest.NewRecorder()
		out := &flushWriter{w: rec}
		out.Write([]byte(tc.output))
		out.endLine()
		out.Write([]byte("__BROKER_EXIT__ 0\n"))
		if got := rec.Body.String(); got != tc.want {
			t.Errorf("after %q: %q, want %q", tc.output, got, tc.want)
		}
	}
}

// fakeDocker puts a docker on PATH that reports whether it has a terminal, then exits 4.
func fakeDocker(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nif [ -t 1 ]; then echo \"tty $(stty size) $TERM\"; else echo plain; fi\nexit 4\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

func TestATerminalClientGetsDockerOnATerminal(t *testing.T) {
	fakeDocker(t)
	rec := httptest.NewRecorder()
	(&broker{}).handle(rec, httptest.NewRequest(http.MethodPost, "/ps?tty=1&rows=30&cols=90", nil))
	if got, want := rec.Body.String(), "tty 30 90 xterm-256color\r\n__BROKER_EXIT__ 4\n"; got != want {
		t.Fatalf("body %q, want %q", got, want)
	}
}

func TestAPlainClientGetsPlainDockerOutput(t *testing.T) {
	fakeDocker(t)
	rec := httptest.NewRecorder()
	(&broker{}).handle(rec, httptest.NewRequest(http.MethodPost, "/ps", nil))
	if got, want := rec.Body.String(), "plain\n__BROKER_EXIT__ 4\n"; got != want {
		t.Fatalf("body %q, want %q", got, want)
	}
}
