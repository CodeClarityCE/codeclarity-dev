package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeList writes a compose file list into a temp repo and returns the repo.
func writeList(t *testing.T, body string) string {
	t.Helper()
	repo := t.TempDir()
	path := filepath.Join(repo, composeFilesList)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return repo
}

func TestComposeFileArgsFollowTheListInOrder(t *testing.T) {
	repo := writeList(t, "# dev stack\n.cloud/docker/docker-compose.yaml\n\n  api/.cloud/docker/docker-compose.yaml  \n# end\n")
	args, err := composeFileArgs(repo)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-f", filepath.Join(repo, ".cloud/docker/docker-compose.yaml"),
		"-f", filepath.Join(repo, "api/.cloud/docker/docker-compose.yaml"),
	}
	if !slices.Equal(args, want) {
		t.Fatalf("got %v, want %v", args, want)
	}
}

func TestComposeFileArgsRefuse(t *testing.T) {
	cases := map[string]string{
		"an empty list":    "# nothing\n\n",
		"an absolute path": "/etc/compose.yaml\n",
		"a path outside":   "../other/docker-compose.yaml\n",
		"a hidden way out": "api/../../docker-compose.yaml\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := composeFileArgs(writeList(t, body)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestComposeFileArgsNeedTheList(t *testing.T) {
	if _, err := composeFileArgs(t.TempDir()); err == nil {
		t.Fatal("expected an error without the list file")
	}
}

func TestTheRepoListStartsWithTheStackFile(t *testing.T) {
	args, err := composeFileArgs("../..")
	if err != nil {
		t.Fatal(err)
	}
	// The first file names the project and sets the project directory.
	if args[1] != filepath.Join("../..", ".cloud/docker/docker-compose.yaml") {
		t.Fatalf("first file is %s", args[1])
	}
	for i := 1; i < len(args); i += 2 {
		if !strings.HasSuffix(args[i], "docker-compose.yaml") {
			t.Errorf("%s is not a service compose file", args[i])
		}
	}
}
