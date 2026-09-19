# Changelog

## Unreleased

- The release workflow also builds `iroh_tunnel-<tag>-linux-aarch64.zip`
  (on GitHub's arm64 Linux runner), for Raspberry Pis, Graviton hosts and
  Apple-silicon VMs.
- CI: the interop harness is a required job now, after staying green on
  every run since the split; it was advisory while the runner's UDP and
  relay reach were unproven.

## v0.2.0 — 2026-09-19

The API round the terminal player asked for, and releases.

- `connect_tunnel` answers a typed `DialError` — `BadCode`, `Rejected { kind }`,
  `Unreachable { reason, relay_online, elapsed }`, `Local` — instead of an
  `anyhow::Error`. The `Display` text is unchanged, so a binding that matches
  on "rejected" still does. `DialError::is_rejected()`.
- `inspect(code)` — the kind of server a code reaches and its endpoint id,
  without dialling. A client files a server under that identity before the
  first dial.
- `connect_tunnel_staged(code, port, on_stage)` reports each `Stage` (bound,
  relay, connected, handshaken, serving) for a diagnostic that has to say
  which step a hostile network killed.
- `Tunnel::local_url()`.
- `mstream_iroh_version()` in the C ABI, additive: the ABI stays 2. The
  build scripts count 15 symbols now.
- Cargo features: `c-abi` (default) is the C ABI and its runtime; `os-trust`
  checks the relay's TLS against the OS trust store. The environment's proxy
  is honoured either way.
- An offline end-to-end test dials a fake server endpoint in-process through
  the stages, round-trips one request with the loopback token, and is
  refused on a wrong secret.
- The release workflow: every `v*` tag builds the Android `.so`s, the iOS and
  macOS xcframeworks, the Windows `.dll`, the Linux `.so`, the dev client,
  the C header (cbindgen, checked against the committed `include/`), and
  publishes them with `SHA256SUMS` and the SwiftPM checksums.

## v0.1.0 — 2026-09-18

The crate as it left `mstream_music/rust/iroh_tunnel`: ABI 2, iroh 1.1.0,
keyed tunnels, federation guest mode, the in-place credential swap, the
loopback token, the reconnect supervisor.
