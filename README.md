# APK Registry

A small, filesystem-backed APK server for one configured Wolfi-style APK
repository. There is no web UI or database. Package files and generated
indexes are served directly; reads are public by default.

Uploads and deletes use revocable API keys with explicit `read`, `deploy`, and
`delete` permissions. An administrator manages keys through a small HTTP API.
Each key is scoped to the one configured repository.

## Run

Set an administrator username and a strong password (at least 16 characters),
then start the server:

```sh
export APK_REGISTRY_ADMIN_USERNAME=admin
export APK_REGISTRY_ADMIN_PASSWORD="$(openssl rand -hex 32)"
docker compose up --build
```

The service listens on port 8080 and stores packages and API key metadata in
the persistent `packages` volume. `APK_REGISTRY_REPOSITORY` selects the single
repository URL prefix and defaults to `os`. The Compose port is bound to
localhost; terminate TLS at a trusted reverse proxy before exposing the
service. Never expose the admin API over plaintext HTTP.

Local development needs Go and the same admin environment variables:

```sh
make run
```

Useful development checks:

```sh
make fmt
make test
make check
make race
make vulncheck
make build
```

`make check` runs formatting validation, golangci-lint, and the unit tests.
CI pins golangci-lint to v2.15.0; install that version locally before running
`make check`. Its default linter set includes Staticcheck.
`make e2e` runs the full package build, signed upload, restart recovery, and
apko installation test; it requires Docker, Melange, apko, curl, Go, and Python 3.
`make build` writes the server binary to `bin/apk-registry` by default; override
`BINARY` to choose another output path.
`make vulncheck` requires `govulncheck` in `PATH`; CI installs it at a pinned
version before running the target.

All server configuration variables use the `APK_REGISTRY_` prefix:

| Variable | Default | Description |
| --- | --- | --- |
| `APK_REGISTRY_ADMIN_USERNAME` | required | Admin API username |
| `APK_REGISTRY_ADMIN_PASSWORD` | required | Admin API password, at least 16 characters |
| `APK_REGISTRY_REPOSITORY` | `os` | The single repository URL prefix |
| `APK_REGISTRY_PUBLIC_READ` | `true` | Set to `false` to require `read` permission |
| `APK_REGISTRY_PUBLIC_URL` | unset | Public HTTP(S) origin used for signing-key discovery |
| `APK_REGISTRY_LISTEN_ADDR` | `:8080` | HTTP listen address |
| `APK_REGISTRY_STORAGE_ROOT` | `./data` | Package and private API-key storage |
| `APK_REGISTRY_INDEX_SIGNING_KEY` | unset | Optional PEM RSA private key path ending in `.rsa` |
| `APK_REGISTRY_MAX_UPLOAD_SIZE` | `1073741824` | Maximum upload size in bytes |
| `APK_REGISTRY_METRICS_ENABLED` | `true` | Run the separate Prometheus metrics listener |
| `APK_REGISTRY_METRICS_HOST` | `0.0.0.0` | Metrics listener bind host |
| `APK_REGISTRY_METRICS_PORT` | `9094` | Metrics listener port |
| `APK_REGISTRY_METRICS_AUTH_ENABLED` | `true` | Require an API key with the `metrics` permission |

## Logs and metrics

The server writes structured JSON logs to stdout. HTTP access events include a
generated `X-Request-ID`, method, matched route pattern, request path, status,
duration, and response size. The path is capped at 256 characters and excludes
the query string; credentials and authorization headers are not logged. Request
paths can contain package names. Metrics continue to use route patterns to avoid
high-cardinality labels.

Prometheus metrics are served at `/metrics` on the separate metrics listener
(default `0.0.0.0:9094`), not on the application listener. They include HTTP
request counts and durations, index build outcomes and durations, index retries,
and Go runtime/process metrics. Authentication is enabled by default and
requires an API key with only the `metrics` permission. Disable it only when
network policy or firewall rules restrict the listener to trusted monitoring
systems.

Create a dedicated scrape key through the administrator API:

```sh
curl --fail-with-body --user "$APK_REGISTRY_ADMIN_USERNAME:$APK_REGISTRY_ADMIN_PASSWORD" \
  -H 'Content-Type: application/json' \
  -d '{"name":"prometheus","permissions":["metrics"]}' \
  https://packages.example.com/api/v1/admin/tokens
```

Configure Prometheus to send the returned key as a bearer token. The key cannot
read, upload, or delete packages. The metrics listener can be disabled or
rebound with the `APK_REGISTRY_METRICS_*` settings above.

When index signing is enabled, the registry derives the public key from the
configured private key and serves it as
`/<repository>/<key-name>.rsa.pub`. It also supports APK key discovery at
`/<repository>/apk-configuration`, which points clients such as apko to the
registry's JWKS endpoint. A signing key named `registry.rsa` is therefore
published as `/<repository>/registry.rsa.pub`; no separate public-key secret
or manual apko `keyring` entry is needed. Use an unencrypted PKCS#1 RSA PEM
key, such as the output of `melange keygen`, and keep the `.rsa` filename
suffix. Set `APK_REGISTRY_PUBLIC_URL` to the external origin (for example
`https://packages.example.com`) when TLS is terminated at a reverse proxy, so
discovery advertises HTTPS URLs.
Mount the private key read-only from a secret, and ensure its file permissions
allow the registry process to read it without granting access to unrelated
users. The container runs the server as UID 10001; do not bake the key into the
image.

## Create and revoke API keys

Create a key with only the permissions it needs. The plaintext value is
returned once; the server stores only its SHA-256 hash:

```sh
curl --fail-with-body --user "$APK_REGISTRY_ADMIN_USERNAME:$APK_REGISTRY_ADMIN_PASSWORD" \
  -H 'Content-Type: application/json' \
  -d '{"name":"github-release","permissions":["deploy"],"expires_at":"2027-01-01T00:00:00Z"}' \
  https://packages.example.com/api/v1/admin/tokens
```

`expires_at` is optional and must be a future RFC3339 timestamp. Omit it for a
key that remains valid until revoked. Expired keys are rejected automatically;
the expiration is included in key metadata.

Available permissions:

- `read`: access packages and indexes when `public_read` is disabled.
- `deploy`: upload new package versions.
- `delete`: delete packages and overwrite an existing package (overwriting
  requires both `deploy` and `delete`).
- `metrics`: scrape Prometheus metrics without package or administrator access.

List key metadata without revealing secrets:

```sh
curl --fail-with-body --user "$APK_REGISTRY_ADMIN_USERNAME:$APK_REGISTRY_ADMIN_PASSWORD" \
  https://packages.example.com/api/v1/admin/tokens
```

Revoke a key by its returned `id`:

```sh
curl --fail-with-body --user "$APK_REGISTRY_ADMIN_USERNAME:$APK_REGISTRY_ADMIN_PASSWORD" \
  -X DELETE https://packages.example.com/api/v1/admin/tokens/KEY_ID
```

Key metadata is stored in a private `_registry` subdirectory of the persistent
storage volume with restrictive filesystem permissions. No plaintext API key
is written to disk.

## Upload and download

The single repository uses the Wolfi-style path layout:
`/<repository>/<architecture>/<file>`. With the default prefix, a package URL
is:

```text
/os/<architecture>/<package>.apk
```

The index is beside the packages at
`/<repository>/<architecture>/APKINDEX.tar.gz`. The registry accepts the
APK architectures supported by Melange: `x86`, `x86_64`, `aarch64`, `armhf`,
`armv7`, `loongarch64`, `ppc64le`, `riscv64`, and `s390x`. Uploads to other
architecture paths are rejected. There are no branch or component path
segments.

Upload a package with an API key:

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $APK_REGISTRY_TOKEN" \
  -T foo-1.2.3-r0.apk \
  https://packages.example.com/os/x86_64/foo-1.2.3-r0.apk
```

Delete a package when the key has `delete` permission:

```sh
curl --fail-with-body -X DELETE \
  -H "Authorization: Bearer $APK_REGISTRY_TOKEN" \
  https://packages.example.com/os/x86_64/foo-1.2.3-r0.apk
```

Unauthenticated reads work by default. Set `APK_REGISTRY_PUBLIC_READ=false` to
require a key with `read` permission. There are no directory listings or package
management UI. Uploads are parsed with apko and checked against the requested
filename and architecture before they are accepted.

### Use an authenticated repository with apk

When reads are private, create an API key with `read` permission. Configure
apk's repository URL and a host-specific `.netrc` entry so the key is sent only
to this server:

```sh
apk_netrc="$(mktemp)"
trap 'rm -f "$apk_netrc"' EXIT
printf 'machine packages.example.com\n  login token\n  password %s\n' \
  "$APK_REGISTRY_READ_TOKEN" > "$apk_netrc"
chmod 600 "$apk_netrc"
printf '%s\n' 'https://packages.example.com/os' >> /etc/apk/repositories
NETRC="$apk_netrc" apk update
```

The login value is ignored by the registry; the API key is supplied as the
Basic-auth password. Keep the repository on HTTPS. The server issues the Basic
authentication challenge apk needs before it reads credentials from `.netrc`.

## GitHub Actions

Create a key with only the required permissions, then save the returned
plaintext value as the repository or environment secret
`APK_REGISTRY_TOKEN`:

```yaml
permissions:
  contents: read

steps:
  - name: Upload package
    env:
      APK_REGISTRY_TOKEN: ${{ secrets.APK_REGISTRY_TOKEN }}
    run: |
      curl --fail-with-body \
        -H "Authorization: Bearer $APK_REGISTRY_TOKEN" \
        -T dist/foo-1.2.3-r0.apk \
        "https://packages.example.com/os/x86_64/foo-1.2.3-r0.apk"
```

Keys without an expiration remain valid until revoked. Keep permissions
narrow, store tokens only in GitHub Secrets, and revoke them when workflows or
maintainers change.

## Dependency updates

Renovate runs hourly, on changes to `.renovaterc.json5` or `.renovate/`, and
manually through the Renovate workflow's dispatch inputs. It updates Go modules
and GitHub Actions, keeping workflow actions pinned to commit SHAs.

Configure these repository secrets:

- `BOT_APP_ID`: the GitHub App client ID.
- `BOT_APP_PRIVATE_KEY`: the App's private key PEM.
- `BOT_GITHUB_TOKEN`: a token with read access to `d4rkfella` packages in
  GHCR, used when Renovate inspects private container images.

Install the App on this repository and grant it read/write access to contents,
pull requests, issues, checks, commit statuses, and workflows, plus read access
to Dependabot alerts. The workflow requests only these permissions when it
creates the short-lived installation token. This uses the App private key
secret to mint that token; it does not use GitHub OIDC.

## Indexing and storage

Uploads and deletes enqueue an index rebuild and return without waiting for
index generation, so clients may briefly see the previous index after a
mutation. Each architecture's batch becomes eligible after an initial 100 ms
window, allowing upload bursts to share fewer index generations; work may wait
longer if another index build is running. Rebuilds use a consistent package
snapshot; publication is atomic, and failed builds are logged and retried. On
startup, existing package directories are scanned to recover pending indexes.
For v2, the first build, overwrites, deletes, and recovery use a full rebuild;
new package uploads are merged into the current index using only the newly
added packages. Full rebuilds use Melange's Go index library. Incremental merges
reuse a per-architecture decoded index cache and use apko's APK metadata/archive
implementation; the cache is refreshed only after generating an output and is
validated against the published index file. Optional signing uses
`APK_REGISTRY_INDEX_SIGNING_KEY`. When a supported architecture is requested
before any packages have been uploaded, the registry creates and serves a valid
empty index (signed when configured); the first package upload is merged into
it.

Run `go test ./internal/registry -run '^$' -bench '^BenchmarkMelangeIndexGeneration$' -benchtime=10x -benchmem`
to compare full rebuilds and 1/10/100-package incremental merges against
100-, 1,000-, and 10,000-package indexes.

`APK_REGISTRY_STORAGE_ROOT` defaults to `./data`; `APK_REGISTRY_MAX_UPLOAD_SIZE`
defaults to 1 GiB.
`/healthz` is a liveness check; `/readyz` reports whether the server is ready
for traffic and returns `503` during shutdown. Use `/healthz` for the
Kubernetes liveness probe and `/readyz` for readiness.

On `SIGTERM` or `SIGINT`, the server marks itself unready, stops accepting new
connections, drains in-flight HTTP requests for up to 20 seconds, then stops
and waits for the index workers. If shutdown is interrupted, startup recovery
rebuilds indexes from the persisted packages.

## Releases

Push a `v*` tag (for example, `v1.2.3`) to run the release workflow. It runs
the test suite and a signed-package end-to-end test before publishing Linux
amd64 and arm64 archives with SPDX SBOMs and a signed checksum file, plus a
multi-architecture image to `ghcr.io/d4rkfella/apk-registry`. Stable tags also
update `latest`; prereleases only receive their version tag. The workflow signs
release checksums and image digests with GitHub OIDC through Cosign, so no
signing key secret is required.

The end-to-end test first runs apko against a fresh, empty signed repository,
then uses Melange to build and sign a hello-world APK, uploads it to that
registry, and runs apko again using the registry's automatic signing-key
discovery. It verifies the package file is present in the resulting image. To
run it locally, install the matching Melange (`v0.65.0`) and apko (`v1.4.15`)
versions and ensure Docker is available, then run `make e2e`.

The GoReleaser image build uses `Dockerfile.goreleaser` to package its
prebuilt binaries. The regular `Dockerfile` remains available for local
`docker compose up --build` development.
