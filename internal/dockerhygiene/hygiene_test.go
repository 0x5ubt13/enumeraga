package dockerhygiene

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root %s has no go.mod: %v", root, err)
	}
	return root
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), rel)) //nolint:gosec // test fixture path is a hard-coded relative path
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	return string(data)
}

func TestDockerfilesDoNotBakeGithubTokenAsArg(t *testing.T) {
	for _, rel := range []string{"Dockerfile", "internal/cloud/Dockerfile"} {
		body := readRepoFile(t, rel)
		if strings.Contains(body, "ARG GITHUB_TOKEN") {
			t.Errorf("%s declares ARG GITHUB_TOKEN, which docker history can recover; use a BuildKit secret", rel)
		}
	}
}

func TestGithubAPICallsMountOptionalTokenSecret(t *testing.T) {
	const mount = "--mount=type=secret,id=github_token"
	for _, rel := range []string{"Dockerfile", "internal/cloud/Dockerfile"} {
		body := readRepoFile(t, rel)
		if !strings.Contains(body, "api.github.com") {
			continue
		}
		if !strings.Contains(body, mount) {
			t.Errorf("%s talks to api.github.com without %s", rel, mount)
		}
	}
}

func TestDockerBuildWorkflowPassesGithubTokenAsSecret(t *testing.T) {
	body := readRepoFile(t, ".github/workflows/docker-build.yml")
	if strings.Contains(body, "GITHUB_TOKEN=") && strings.Contains(body, "build-args:") {
		// A token in build-args is the leak this change exists to close.
		for _, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "GITHUB_TOKEN=") {
				t.Errorf("docker-build.yml passes GITHUB_TOKEN as a build-arg: %s", trimmed)
			}
		}
	}
	if !strings.Contains(body, "github_token=${{ secrets.GITHUB_TOKEN }}") {
		t.Error("docker-build.yml does not pass github_token as a BuildKit secret to the image builds")
	}
}

func lastDockerfileUser(body string) string {
	user := ""
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "USER ") {
			user = strings.TrimSpace(strings.TrimPrefix(trimmed, "USER "))
		}
	}
	return user
}

func TestMCPServerDockerfileDropsRoot(t *testing.T) {
	user := lastDockerfileUser(readRepoFile(t, "mcp-server-enumeraga/Dockerfile"))
	if user == "" {
		t.Fatal("mcp-server-enumeraga/Dockerfile has no USER; the server would run as root")
	}
	if user == "root" || user == "0" || user == "0:0" {
		t.Errorf("mcp-server-enumeraga/Dockerfile ends on USER %s; the server must not run as root", user)
	}
}

func TestMCPComposeAddsDockerSocketGroup(t *testing.T) {
	body := readRepoFile(t, "mcp-server-enumeraga/docker-compose.yml")
	if !strings.Contains(body, "group_add:") {
		t.Fatal("docker-compose.yml has no group_add; a non-root server cannot open the host docker socket")
	}
	if !strings.Contains(body, "DOCKER_GID") {
		t.Error("group_add does not take DOCKER_GID, so the operator cannot match the host socket's group")
	}
}
