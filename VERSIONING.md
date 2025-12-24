# Versioning Guide

Enumeraga uses **semantic versioning** with **automatic version injection** at build time.

## How It Works

Version information is automatically embedded into the binary during build using git tags and commit information.

### Version Components

- **Version**: Semantic version from git tags (e.g., `v0.2.1-beta`)
- **GitCommit**: Short commit hash (e.g., `084147d`)
- **BuildDate**: UTC timestamp when binary was built

### Build Process

The Makefile automatically injects version info:

```bash
# Regular build (uses git describe for version)
make build

# Result: enumeraga v0.2.1-beta-1-g084147d (commit: 084147d, built: 2025-12-24_10:17:51)
```

### Checking Version

```bash
# Show version
./enumeraga --version
./enumeraga -v

# Development builds show:
enumeraga development build

# Release builds show:
enumeraga v0.2.1-beta (commit: 084147d, built: 2025-12-24_10:17:51)
```

## Creating Releases

### 1. Tag a New Version

Follow semantic versioning: `vMAJOR.MINOR.PATCH[-PRERELEASE]`

```bash
# Beta release
git tag v0.2.2-beta
git push origin v0.2.2-beta

# Release candidate
git tag v0.3.0-rc1
git push origin v0.3.0-rc1

# Stable release
git tag v0.3.0
git push origin v0.3.0
```

### 2. Automatic Release Build

When you push a tag, GitHub Actions automatically:
1. Builds binaries for multiple platforms (Linux amd64/arm64, macOS amd64/arm64)
2. Injects version information
3. Creates GitHub release
4. Uploads binaries and checksums
5. Marks as pre-release if tag contains `alpha`, `beta`, or `rc`

### 3. Manual Local Build

**Binary Build:**
```bash
# Build with current git info
make build

# Build for specific platform
GOOS=linux GOARCH=amd64 go build -ldflags="-X github.com/0x5ubt13/enumeraga/internal/utils.Version=v0.2.2-beta ..." -o enumeraga main.go
```

**Docker Build:**
```bash
# Build infra image with version info
VERSION=$(git describe --tags --always --dirty)
COMMIT=$(git rev-parse HEAD)
DATE=$(date -u '+%Y-%m-%d_%H:%M:%S')

docker build \
  --build-arg VERSION=$VERSION \
  --build-arg GIT_COMMIT=$COMMIT \
  --build-arg BUILD_DATE=$DATE \
  -t gagarter/enumeraga_infra:$VERSION \
  .

# Build cloud image with version info
docker build \
  --build-arg VERSION=$VERSION \
  --build-arg GIT_COMMIT=$COMMIT \
  --build-arg BUILD_DATE=$DATE \
  -t gagarter/enumeraga_cloud:$VERSION \
  -f internal/cloud/Dockerfile \
  .

# Verify version in container
docker run --rm gagarter/enumeraga_infra:$VERSION --version
```

## Version Naming Convention

### Format: `vMAJOR.MINOR.PATCH[-PRERELEASE]`

**MAJOR**: Breaking changes
- Example: `v1.0.0` → `v2.0.0`

**MINOR**: New features, backward compatible
- Example: `v0.2.0` → `v0.3.0`

**PATCH**: Bug fixes, backward compatible
- Example: `v0.2.1` → `v0.2.2`

**PRERELEASE**: Alpha, Beta, Release Candidate
- `v0.2.2-alpha` - Very early testing
- `v0.2.2-beta` - Feature complete, testing
- `v0.2.2-rc1` - Release candidate
- `v0.2.2` - Stable release

### Examples

```bash
# Alpha - new feature in early testing
git tag v0.3.0-alpha

# Beta - feature complete, needs testing
git tag v0.3.0-beta

# Release candidate
git tag v0.3.0-rc1
git tag v0.3.0-rc2

# Stable release
git tag v0.3.0

# Patch release
git tag v0.3.1
```

## CI/CD Pipelines

### Docker Image Builds (`.github/workflows/docker-build.yml`)

Triggered on:
- Push to `main` or `develop` branches
- Pull requests to `main`
- Git tags matching `v*.*.*`

Builds both images with version info:
1. Gets version from `git describe`
2. Passes as build args: `VERSION`, `GIT_COMMIT`, `BUILD_DATE`
3. Builds multi-platform: `linux/amd64`, `linux/arm64`
4. Pushes to Docker Hub with multiple tags:
   - `latest` (main branch only)
   - `main-<commit_sha>` (branch builds)
   - `v0.2.1-beta` (tag builds)
   - `v0.2` and `v0` (semver tags)

### Binary Releases (`.github/workflows/release.yml`)

Triggered on git tags: `v*.*.*` or `v*.*.*-*`

Builds binaries for:
- Linux amd64/arm64
- macOS amd64/arm64

Each binary includes version info and is uploaded to GitHub Releases with checksums.

## Implementation Details

### Code Location

- **Version variables**: `internal/utils/utils.go` (lines 82-84)
- **GetVersion()**: `internal/utils/utils.go` (lines 110-120)
- **Version flag**: `internal/checks/checks.go` (line 52)
- **Build injection**: `Makefile` (lines 64-70)
- **Binary releases**: `.github/workflows/release.yml`
- **Docker builds**: `.github/workflows/docker-build.yml`

### Build Flags

The Makefile uses `-ldflags` to inject values at compile time:

```bash
-X github.com/0x5ubt13/enumeraga/internal/utils.Version=$VERSION
-X github.com/0x5ubt13/enumeraga/internal/utils.GitCommit=$COMMIT
-X github.com/0x5ubt13/enumeraga/internal/utils.BuildDate=$DATE
```

### Git Describe Format

`git describe --tags --always --dirty` produces:
- `v0.2.1-beta` - Exact tag match
- `v0.2.1-beta-5-g084147d` - 5 commits after tag v0.2.1-beta
- `v0.2.1-beta-dirty` - Uncommitted changes
- `084147d` - No tags found, uses commit hash

## Development Workflow

### Local Development

```bash
# Build dev version
make build
# Shows: enumeraga development build

# Commit changes
git add .
git commit -m "feat: add new feature"
make build
# Shows: enumeraga v0.2.1-beta-1-g084147d (...)
```

### Creating a Release

```bash
# 1. Update CHANGELOG.md with changes
# 2. Commit all changes
git add .
git commit -m "chore: prepare v0.3.0-beta release"

# 3. Create and push tag
git tag v0.3.0-beta
git push origin main
git push origin v0.3.0-beta

# 4. GitHub Actions builds and releases automatically
# 5. Check https://github.com/0x5ubt13/enumeraga/releases
```

## Troubleshooting

### "development build" shows instead of version

- No git tags exist: `git tag v0.1.0`
- Not in a git repo: Ensure `.git` directory exists
- Build outside git: Version defaults to "dev"

### Wrong version shows

- Uncommitted changes: Commit or stash changes
- Wrong tag: Check `git describe --tags`
- Old binary: Rebuild with `make build`

### GitHub Action fails

- Check tag format: Must start with `v` (e.g., `v0.2.1-beta`)
- Check permissions: Repository needs write access for releases
- Check workflow file: `.github/workflows/release.yml`

## References

- [Semantic Versioning](https://semver.org/)
- [Git Tagging](https://git-scm.com/book/en/v2/Git-Basics-Tagging)
- [Go Build ldflags](https://pkg.go.dev/cmd/go#hdr-Compile_packages_and_dependencies)
