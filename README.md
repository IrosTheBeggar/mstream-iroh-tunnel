# mstream-iroh-tunnel

The client side of mStream's iroh remote-access tunnel, as a Rust library and
a C ABI. Given a **Quick Connect pairing code** (`mstr1:…`, from a server's
admin panel) or a **federation guest ticket** (`mstrfedg1:…`, handed to a
device by its own server for one of that server's federated peers), it dials
the server's iroh endpoint, completes the handshake, and exposes the server as
a **plain local HTTP origin** — `http://127.0.0.1:<port>` — so an ordinary HTTP
client, range requests and all, works against it unchanged. mStream's own
auth still gates the API inside the tunnel.

One implementation, three consumers:

| Consumer | How |
|---|---|
| [mstream_music](https://github.com/IrosTheBeggar/mstream_music) — the Flutter app (Android, iOS, macOS, Windows) | the C ABI (`mstream_iroh_*`, [src/c_api.rs](src/c_api.rs)) through `dart:ffi`, loading the per-platform binary the `build-*.sh` scripts produce |
| [mstream-terminal-player](https://github.com/IrosTheBeggar/mstream-terminal-player) — Rust | the crate as a Cargo dependency (`connect_tunnel`, `Tunnel`) |
| anything else | either of the above; `iroh-tunnel-client` ([src/bin/client.rs](src/bin/client.rs)) is the reference: dial a code, get a local port |

It is a faithful port of the server's reference client
(`scripts/mstream-iroh-client.mjs` in the
[mStream](https://github.com/IrosTheBeggar/mStream) repo, PR #643), and it
moved here from `rust/iroh_tunnel` in the mobile app's repository on
2026-09-18, history included. The wire specs stay in the mStream repo:
`docs/iroh-pairing-code.md`, `docs/federation-guest-ticket.md` and
`docs/federation-ticket.md`.

## Frozen wire contract (must match the server byte-for-byte)

- Pairing code = versioned envelope `mstr<V>:<base64url(JSON{ t: <EndpointTicket>, s: <connectSecret base64> })>` (spec: mStream `docs/iroh-pairing-code.md`). v1 current; a bare (un-prefixed) body is legacy implicit v1; a newer version is rejected with an "update the app" error. secret = 32 bytes.
- ALPN = `mstream/tunnel/2`.
- Bind an ephemeral endpoint, wait for our home relay (`online()`, bounded) **before** dialing.
- Handshake on the **first** bi-stream: write the 32 secret bytes, then expect ASCII `"OK"` (a `"NO"`/reset means the secret was wrong or rotated → re-pair).
- **Guest mode** (mStream federation, `docs/federation-guest-ticket.md` there): a `mstrfedg<V>:<base64url(JSON{ t: <EndpointTicket>, g: <guest JWT> })>` ticket dials ALPN `mstream/federation/1` and writes the token bytes (≤ 2 KB, the peer's `HANDSHAKE_LIMIT`) on the first bi-stream; `"OK"`/`"NO"` as above, where `"NO"` means the token expired or its key was revoked → refresh it from the parent (`set_credential`), no re-pair. A `mstrfed<V>:` federation ticket (admin-to-admin, carries a standing key) is refused by name.
- Then **one bi-stream per inbound local TCP connection**; raw byte pipe both ways (one bi-stream == one TCP connection → full HTTP semantics, incl. range/seek). Clean EOF → `finish`/`shutdown`; either side erroring → `reset`/`stop` the partner.

## What the client does beyond the wire

- **Keyed tunnels.** The `ffi` table holds tunnels by an app-chosen key, so a
  Quick Connect server and a directly reached federated peer run side by
  side, each on its own loopback port with its own supervisor.
- **A reconnect supervisor.** Exponential backoff, cut short by an app kick
  (`force_reconnect`) or by the home relay coming back; `force_reconnect`
  re-binds the loopback listener on the **same** port and closes the current
  connection so the supervisor re-dials at once (iOS kills the listener
  during a suspension while QUIC survives); bridges wait up to 10 s for a
  swapped-in connection.
- **In-place credential swap** (`set_credential`). A guest token is renewed
  daily and the renewal must not rotate the loopback port; a supervisor that
  gave up on a rejected handshake re-dials at once with the new credential.
- **Loopback auth.** Each tunnel has a random token that every local request
  must carry as `__lt=<token>` in its request line, so other processes on
  the device cannot use the proxy.
- **Status** (`connecting / connected / reconnecting / rejected / down`),
  **path kind** (direct or relay), the home-relay state, and an events ring
  for a diagnostics log.
- **ABI version 2** (`mstream_iroh_abi_version`): a binding refuses an older
  binary, whose `start` took different arguments.

## Use it from Rust

```toml
[dependencies]
mstream-iroh-tunnel = { git = "https://github.com/IrosTheBeggar/mstream-iroh-tunnel", tag = "v0.1.0" }
```

```rust
let tunnel = iroh_tunnel::connect_tunnel(code, 0).await?; // 0 = an ephemeral port
let base = format!("http://127.0.0.1:{}", tunnel.local_port);
let lt = tunnel.local_token(); // append ?__lt=<lt> to every request
```

The library keeps its historical name, `iroh_tunnel`, so that the shipped
artifacts and the C symbols never changed — hence the `iroh_tunnel::` path.
`Tunnel::set_credential`, `force_reconnect`, `nudge_network` and
`begin_shutdown` take a `&tokio::runtime::Runtime`; the `ffi` module owns one
for bindings that have no ambient runtime.

## Use it from another language

Build a binary (below) and call the C ABI — 14 symbols, declared in
[src/c_api.rs](src/c_api.rs): `mstream_iroh_abi_version`,
`mstream_iroh_start(key, code, port)` → the loopback port, `mstream_iroh_stop`,
`_is_active`, `_status`, `_path_kind`, `_network_changed`, `_force_reconnect`,
`_set_credential`, `_drain_events`, `_relay_online`, `_local_token`,
`_last_error`, `_string_free`. The mobile app's binding
(`lib/native/iroh_tunnel.dart` in its repo) is the worked example.

## Run the interop test (desktop, no device needed)

```sh
cd interop && npm install          # @number0/iroh 1.1.0 — the line the mStream server runs
cd .. && cargo build               # builds the dev client binary
node interop/harness.mjs           # Rust client ⇆ JS server; asserts JSON + Range + concurrency + reconnect + in-place kick + a spent kick not cutting the next backoff + guest mode (federation ALPN, rejected token, in-place credential swap)
```

`interop/pairing-server.mjs` is the server half on its own, kept alive for
manual testing of a client build: it prints a pairing code to paste in.

## Build the binaries

Every script stages into `dist/<platform>/` by default, or into
`$IROH_TUNNEL_DEST` when that is set — a consumer's own tree, for example
the mobile app's `jniLibs` folder. Release builds are size-optimized
(`opt-level = "z"`, thin LTO, stripped; see `[profile.release]`) — rustc
strips cdylibs with `strip -x`, which keeps the exported C symbols.

- **Android** — `rustup target add aarch64-linux-android x86_64-linux-android`,
  `cargo install cargo-ndk`, `export ANDROID_NDK_HOME=…`; then
  `./build-android.sh` → `dist/android/{arm64-v8a,x86_64}/libiroh_tunnel.so`
  (API 26, ~10 MB each: iroh core only, no blobs/docs/gossip/rpc).
- **iOS** — `rustup target add aarch64-apple-ios aarch64-apple-ios-sim` and
  the Xcode command line tools; `./build-ios.sh` →
  `dist/ios/iroh_tunnel.xcframework` (device + simulator arm64, minos 15.0).
  The script fails if all 14 symbols are not exported from both slices, or if
  the iOS 18-only `nw_path_is_ultra_constrained` import ever returns (it
  crashed the app at launch on iOS 15–17 once).
- **macOS** — `./build-macos.sh` → `dist/macos/iroh_tunnel.xcframework`
  (arm64, minos 11.0).
- **Windows / Linux** — a host `cargo build --release --lib` →
  `target/release/iroh_tunnel.dll` or `libiroh_tunnel.so`. The Android-only
  dependencies are `cfg`-gated; nothing else is platform-specific.

Consumers that ship a binary commit it on their side (the mobile app's
release CI has no Rust toolchain); a stale committed binary is the one
failure their packaging checks cannot detect, so a bump here means re-staging
and re-committing there. Tag-driven release assets with checksums are on the
roadmap, so that step becomes a download.

## Layout

| Path | Role |
|---|---|
| `src/lib.rs` | async core: credential parse, connect, handshake, the byte-pump bridge, the supervisor. |
| `src/ffi.rs` | owned global Tokio runtime + the tunnel table keyed by the app's id: `tunnel_start(key, code, port)`, `tunnel_stop(key)`, `tunnel_set_credential(key, code)`, … (a `dart:ffi` caller has no ambient runtime, so it `block_on`s). |
| `src/c_api.rs` | `#[no_mangle]` C ABI (`mstream_iroh_*`). |
| `src/android_init.rs` | Android only: registers the JavaVM + app Context with `ndk_context` (iroh's network monitoring needs it). |
| `src/bin/client.rs` | dev CLI; drives the same `ffi` path the app uses. |
| `interop/harness.mjs` | stands up the server side on `@number0/iroh` and drives the compiled Rust client through real HTTP. |
| `interop/pairing-server.mjs` | the server side alone, for manual client testing. |
| `build-android.sh`, `build-ios.sh`, `build-macos.sh` | cross-compile and stage the binaries. |

## Binding choice: C ABI + `dart:ffi` (not flutter_rust_bridge)

The surface is small (abi-version, start / stop / status / path-kind / network-changed / local-token / last-error, force-reconnect / drain-events / relay-online, set-credential, string-free — 14 symbols), so a hand-written C ABI consumed via `dart:ffi` is lighter than a codegen step in the build — one binary plus a small wrapper on the other side. A generated binding remains an option if a richer or streaming surface is ever needed. The Dart side probes `mstream_iroh_abi_version` first and reports the tunnel as unsupported (with the reason in `IrohTunnel.unsupportedReason`) against a binary older than ABI v2, whose `start` takes different arguments — refusing beats misreading.

## Roadmap

- A tag-driven release workflow: per-platform binaries, `SHA256SUMS`, a
  generated C header.
- Cargo features `c-abi` (default; off for Rust consumers so no
  `#[no_mangle]` symbols land in their binaries) and `os-trust` (iroh's
  `platform-verifier`, for hosts behind a corporate trust store).
- Typed dial errors (rejected, unreachable, bad code) instead of matching the
  error text; a staged connect (bind, relay, dial, handshake) so a diagnostic
  can say which stage died; `mstream_iroh_version()`.
- crates.io.

The consumers' migration plan lives in the mobile app repo
(`IROH_TUNNEL_CRATE_PLAN.md`).

## History

- **2026-06** — the Android client shim (M1) for mStream PR #643; interop
  proven on desktop against a replica of the server.
- **2026-09** — self-healing in place (the kick, the same-port re-bind, the
  events ring); keyed tunnels and federation guest mode (ABI v2); iroh 1.1.0
  (a lockfile update that cleared four `cargo audit` advisories).
- **2026-09-18** — split out of `mstream_music/rust/iroh_tunnel` as this
  repository.
