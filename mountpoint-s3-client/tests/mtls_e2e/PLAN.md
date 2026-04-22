# mTLS end-to-end test harness — plan

This directory will hold a hermetic, Docker-based end-to-end test for the mTLS support added to `mountpoint-s3-client` (new `TlsConfig`, plus the underlying `mountpoint-s3-crt::io::tls` module and `s3::client::ClientConfig::tls_connection_options` builder).

The goal: prove on a developer Mac — with zero real AWS credentials and no macFUSE — that a client configured with `TlsConfig { ca_bundle, client_cert, client_key }` successfully completes a TLS handshake against a server that mandates client cert verification and issues a real S3-shaped HTTP request through that channel.

## Why this exists

- The PEM-based mTLS path in the client is Linux-only (`#[cfg(target_os = "linux")]` around `TlsContextOptions::set_client_mtls_from_path`). Running in a Linux container inside Docker Desktop is the only way to exercise it from a Mac dev loop.
- The FUSE layer is orthogonal to TLS — nothing about mounting a filesystem changes how the HTTPS connection to S3 is made. Testing at the `mountpoint-s3-client` level is enough to prove the feature. FUSE-layer mTLS testing would require `--privileged` / `/dev/fuse` and is deferred.
- Existing tests in `mountpoint-s3-client/tests/` hit real AWS behind `#[cfg(feature = "s3_tests")]`. This harness sits alongside them but is driven by a helper script (`run-mtls-e2e.sh`) and opts in via a new `mtls_tests` Cargo feature, so it never runs during ordinary `cargo test`.

## Architecture

Three collaborating pieces, all orchestrated by a single `docker compose` invocation that `run-mtls-e2e.sh` wraps.

1. **Certificate generator** — a one-shot init container (using `alpine/openssl` or similar) that produces, in a named volume:
   - `ca.pem` + `ca.key` (self-signed CA, 10-year validity)
   - `server.pem` + `server.key` (signed by CA, SAN = `mtls-nginx`, the nginx container name)
   - `client.pem` + `client.key` (signed by CA, CN = `mountpoint-test-client`)
   
   Idempotent: if the volume already contains valid PEMs, the generator short-circuits.

2. **mTLS-terminating mock S3 server** — `nginx:alpine` configured with:
   - Listens on `https://mtls-nginx:443`.
   - `ssl_verify_client on; ssl_client_certificate /certs/ca.pem;` — refuses the handshake if the client doesn't present a cert signed by our CA.
   - Serves a canned `ListObjectsV2` XML response for any `GET /?list-type=2` request, and a canned `200 OK` with a small body for any `GET /{key}`.
   - No real S3 logic — the test only needs to prove a round trip works through mTLS. A full S3 protocol mock would be overkill.

3. **Test runner container** — built from a local `Dockerfile.builder`:
   - Base: `rust:bookworm`.
   - Installs CRT build deps: `cmake`, `pkg-config`, `libssl-dev`, `libclang-dev`, `git`.
   - Mounts the repo read-write so `target/` is cached on a named volume across runs.
   - Runs `cargo test -p mountpoint-s3-client --features mtls_tests --test mtls_e2e -- --nocapture`.
   - Has `/certs/` bind-mounted from the cert-gen volume so the test can point `TlsConfig` at the PEMs.

All three sit on a private Docker network so hostnames resolve. The test container waits for nginx to be reachable before running `cargo test` (a small `wait-for-it`-style loop in the entrypoint).

## Directory layout

```
mountpoint-s3-client/tests/mtls_e2e/
├── PLAN.md                     # this file
├── docker-compose.yml          # orchestration: certgen → nginx + runner
├── Dockerfile.builder          # rust:bookworm + CRT build deps
├── nginx/
│   ├── nginx.conf              # mTLS server config + canned responses
│   └── canned/                 # XML/text response bodies
│       ├── list-objects-v2.xml
│       └── hello.txt
├── gen-certs.sh                # openssl script, run by certgen container
├── run-mtls-e2e.sh             # developer-facing entry point
└── README.md                   # how to run, what's tested, troubleshooting
```

And one new file in the tests root:

```
mountpoint-s3-client/tests/
└── mtls_e2e.rs                 # the actual Rust test, #[cfg(feature = "mtls_tests")]
```

## `run-mtls-e2e.sh` responsibilities

- Accept `--clean` flag to nuke cached volumes (certs + `target/`) for a pristine run.
- `docker compose build` → build the runner image.
- `docker compose up --abort-on-container-exit --exit-code-from runner` → start certgen, wait, start nginx + runner, propagate the runner's exit code as the script's exit code.
- On failure: dump nginx access/error logs (`docker compose logs nginx`) to make handshake failures diagnosable.
- `docker compose down -v` only on `--clean` or with a `--teardown` flag, not by default — keeps volumes warm for fast iteration.

## The Rust test (`tests/mtls_e2e.rs`)

Under `#[cfg(feature = "mtls_tests")]`. Two test cases to start:

1. **`list_objects_over_mtls`** — construct `S3ClientConfig` with `TlsConfig { ca_bundle: Some("/certs/ca.pem".into()), client_cert: Some("/certs/client.pem".into()), client_key: Some("/certs/client.key".into()) }`, set `endpoint_config` to `EndpointConfig::new("us-east-1").endpoint(Uri::from("https://mtls-nginx"))`, `auth_config` to `S3ClientAuthConfig::NoSigning`. Call `client.list_objects("test-bucket", None, "", 0, "")`. Assert `Ok`.

2. **`list_objects_fails_without_client_cert`** — same config but omit `client_cert`/`client_key`. Call the same method. Assert the error indicates TLS handshake failure (nginx will send a TLS alert, which surfaces as a CRT connection error).

Both tests depend on the cert volume being mounted at `/certs` inside the runner container — that's baked into the compose file, not the test.

## `Cargo.toml` additions

In `mountpoint-s3-client/Cargo.toml`:
```
[features]
# ... existing features ...
mtls_tests = []
```
No new dependencies. The test uses only what's already available.

## First-run experience

- `./run-mtls-e2e.sh` with a cold cache: ~3–5 min on Apple Silicon (CRT build dominates). Cert generation is <1s. nginx starts in <1s.
- Subsequent runs with warm `target/` cache: ~10–20s total (rust compiles only the test, nginx restarts fast).
- The runner container's `target/` is on a named Docker volume (`mtls-e2e-cargo-target`), scoped to this test setup so it won't interfere with host `cargo build`.

## Trade-offs accepted

- **No full S3 protocol fidelity.** nginx is not an S3 server — it returns canned responses. That's fine: the thing we're testing is the mTLS channel, not S3 request semantics. If a `list_objects` response is shaped correctly enough that the CRT parses it, we've proven the plumbing.
- **Self-signed certs only.** No need for a real CA in a test harness.
- **Linux-only validation.** This harness does not (and cannot easily) exercise the `--cfg not(target_os = "linux")` path. That's verified by the existing `tests/tls_config.rs` unit test (`mismatched_client_cert_without_key_fails`) and is a compile-time gate anyway.
- **No TLS version / cipher matrix.** v1 validates "the happy path works." A negative handshake case covers the error path. Fuller matrix testing is follow-up work.

## Open questions for tomorrow

1. **Where do cached cert material and `target/` live?** Named Docker volumes (proposed) keep the repo clean but are opaque to the user. Bind mounts under `tests/mtls_e2e/.cache/` would be transparent but add gitignore noise. Lean toward named volumes with a `./run-mtls-e2e.sh --clean` escape hatch.
2. **Should the runner image be pinned / published?** For local dev, building locally is fine. If we ever want this in CI, pinning to a digest and caching the image via GHCR would be the path.
3. **Do we also want a smoke test of the `mount-s3` binary mounting via mTLS inside a privileged container?** Useful for proving the CLI plumbing end-to-end, but adds `--cap-add SYS_ADMIN --device /dev/fuse` and kernel-level friction. Probably a separate, optional follow-up test.
4. **`#[cfg(feature = "mtls_tests")]` gate vs. runtime detection?** A feature flag means `cargo check --all-features` will pull in the test module even outside the container. That's fine — the test only runs when cargo actually executes it, which only happens inside the container. If we see stray runs, a `#[cfg(all(feature = "mtls_tests", target_os = "linux"))]` belt-and-braces is easy to add.
5. **Does this belong in the upstream awslabs repo?** The nginx+Docker test pattern isn't established in the existing `tests/` directory. Worth asking maintainers in the feature-request issue (see CONTRIBUTING.md) whether they'd prefer this integrated or left as a tool for contributors.

## Estimated work tomorrow

~3–4 hours if everything lands cleanly:
- 45 min: `Dockerfile.builder` + compose + certgen + cert script.
- 45 min: `nginx.conf` with correct S3-shaped responses for the minimum set of requests CRT's `list_objects` issues.
- 45 min: the Rust test file and the `mtls_tests` feature wiring.
- 30 min: `run-mtls-e2e.sh` polish, README, log-dumping on failure.
- Remainder: debugging, cert path issues, nginx response shape tweaks.
