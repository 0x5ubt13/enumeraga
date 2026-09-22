package dockerhygiene

import (
	"os"
	"path/filepath"
	"regexp"
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

func TestFloatingImageAndToolPins(t *testing.T) {
	infra := readRepoFile(t, "Dockerfile")
	if strings.Contains(infra, "FROM kalilinux/kali-rolling") && !strings.Contains(infra, "FROM kalilinux/kali-rolling@sha256:") {
		t.Error("infra Dockerfile FROM kali-rolling is unpinned; pin the multi-arch digest")
	}

	cloud := readRepoFile(t, "internal/cloud/Dockerfile")
	if strings.Contains(cloud, "aws-enumerator@latest") {
		t.Error("cloud Dockerfile installs aws-enumerator@latest; pin a commit")
	}
	if !regexp.MustCompile(`PMapper\.git@[0-9a-f]{40}`).MatchString(cloud) {
		t.Error("cloud Dockerfile installs PMapper from floating git HEAD; pin a commit")
	}

	// cloudfox reads its Azure scope from the command line, so a release that
	// renames those flags makes every Azure inventory run a no-op that still
	// exits 0. Tracking "latest" is what let that happen unnoticed.
	if strings.Contains(cloud, "cloudfox/releases/latest") {
		t.Error("cloud Dockerfile resolves cloudfox from releases/latest; pin a tag")
	}
	if !regexp.MustCompile(`CLOUDFOX_VERSION="v[0-9]+\.[0-9]+\.[0-9]+"`).MatchString(cloud) {
		t.Error("cloud Dockerfile does not pin CLOUDFOX_VERSION to an exact tag")
	}

	if strings.Contains(readRepoFile(t, "internal/commands/commands.go"), "aws-enumerator@latest") {
		t.Error("commands.go installs aws-enumerator@latest; pin a commit")
	}

	mcp := readRepoFile(t, "mcp-server-enumeraga/Dockerfile")
	if regexp.MustCompile(`(?m)^FROM python:3\.11-slim\s*$`).MatchString(mcp) {
		t.Error("MCP Dockerfile FROM python:3.11-slim floats the patch; pin 3.11.x-slim-bookworm")
	}

	compose := readRepoFile(t, "mcp-server-enumeraga/docker-compose.yml")
	if regexp.MustCompile(`(?m)^\s*image:\s*docker:cli\s*$`).MatchString(compose) {
		t.Error("compose image docker:cli floats; pin docker:<version>-cli")
	}
}

// TestCloudfoxPinsAgreeAcrossImageAndRuntime keeps the two places that install
// cloudfox on the same release.
//
// The image installs it at build time and internal/installer downloads it at run
// time when the image's copy is missing. If only the Dockerfile were pinned, that
// fallback would quietly fetch a newer cloudfox mid-scan and reintroduce exactly
// the drift the pin exists to stop.
func TestCloudfoxPinsAgreeAcrossImageAndRuntime(t *testing.T) {
	goSource := readRepoFile(t, "internal/installer/github.go")
	goPin := regexp.MustCompile(`CloudfoxPinnedVersion = "(v[0-9]+\.[0-9]+\.[0-9]+)"`).FindStringSubmatch(goSource)
	if goPin == nil {
		t.Fatal("internal/installer/github.go does not declare CloudfoxPinnedVersion as an exact tag")
	}

	dockerfile := readRepoFile(t, "internal/cloud/Dockerfile")
	dockerPin := regexp.MustCompile(`CLOUDFOX_VERSION="(v[0-9]+\.[0-9]+\.[0-9]+)"`).FindStringSubmatch(dockerfile)
	if dockerPin == nil {
		t.Fatal("internal/cloud/Dockerfile does not pin CLOUDFOX_VERSION to an exact tag")
	}

	if goPin[1] != dockerPin[1] {
		t.Errorf("cloudfox pins disagree: Dockerfile installs %s, runtime fallback downloads %s; raise both together",
			dockerPin[1], goPin[1])
	}
}

// TestRuntimeCloudfoxDownloadIsNotLatest guards the fallback path specifically.
func TestRuntimeCloudfoxDownloadIsNotLatest(t *testing.T) {
	goSource := readRepoFile(t, "internal/installer/github.go")
	if !strings.Contains(goSource, `releasePath = "tags/" + pinnedVersion`) {
		t.Error("the runtime GitHub download no longer resolves a pinned tool by tag; a pinned tool must not fall back to releases/latest")
	}
}
