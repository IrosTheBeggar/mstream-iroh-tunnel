//! mStream iroh remote-access tunnel — Android client core.
//!
//! A faithful port of the server's reference client `scripts/mstream-iroh-client.mjs`
//! (mStream PR #643). The wire protocol is FROZEN by that PR; this matches it
//! byte-for-byte:
//!
//!   * Pairing code = base64url(JSON{ t: <EndpointTicket>, s: <connectSecret b64> }).
//!   * ALPN = "mstream/tunnel/2".
//!   * Bind an ephemeral endpoint, wait for our home relay (`online`) BEFORE dialing.
//!   * Handshake on the FIRST bi-stream: write the 32-byte secret, expect ASCII "OK".
//!   * Then one bi-stream per inbound local TCP connection; raw byte pipe both ways
//!     (one bi-stream == one TCP connection → full HTTP semantics incl. range/seek).
//!
//! The app points its base URL at `http://127.0.0.1:<local_port>` and is otherwise
//! unchanged; mStream's JWT auth still gates the API inside the tunnel.
//!
//! The Dart/Android entry points live in [`ffi`] (owned Tokio runtime + start/stop);
//! [`c_api`] exposes those over a C ABI for `dart:ffi`.

#[cfg(feature = "c-abi")]
pub mod c_api;
#[cfg(feature = "c-abi")]
pub mod ffi;

// Android-only JNI entry point that registers the app Context with ndk_context
// (iroh needs it for network monitoring; without it the first call panics).
#[cfg(target_os = "android")]
mod android_init;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, TransportAddr, Watcher as _};
use iroh_tickets::endpoint::EndpointTicket;
use iroh_tickets::Ticket as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// ALPN both ends must present. Bump if the server bumps `mstream/tunnel/N`.
pub const TUNNEL_ALPN: &[u8] = b"mstream/tunnel/2";
/// The FEDERATION endpoint's ALPN (mStream `src/state/federation.js`) — what a
/// guest ticket dials. The same TCP-over-QUIC bridge sits behind it; only the
/// credential on the first bi-stream differs (a guest token, not a secret).
pub const FEDERATION_ALPN: &[u8] = b"mstream/federation/1";

const READ_CHUNK: usize = 64 * 1024;
const ONLINE_TIMEOUT: Duration = Duration::from_secs(8);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(25);
// Deadline for the post-connect secret handshake. Without it, a half-dead server
// that accepts the bi-stream but never writes "OK"/FIN parks read_to_end forever
// (no idle timeout fires while it answers keep-alives), freezing the supervisor.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_RESP_LIMIT: usize = 8;
const SECRET_LEN: usize = 32;
/// Highest pairing-code schema version this client understands. The pairing-code
/// version (the `mstr<V>:` envelope) is independent of the tunnel ALPN version.
const PAIRING_VERSION: u32 = 1;
/// Highest federation GUEST ticket version (`mstrfedg<V>:`) this client
/// understands — mStream `docs/federation-guest-ticket.md`.
const GUEST_TICKET_VERSION: u32 = 1;
/// The peer reads at most this much on the first bi-stream (mStream's
/// HANDSHAKE_LIMIT), so a longer guest token could never be accepted.
const GUEST_TOKEN_MAX: usize = 2048;

// A request that lands while the supervisor is mid-reconnect waits (bounded)
// for the swapped-in connection instead of hard-failing: ExoPlayer's read
// timeout is 8s and the app's API calls allow 15-20s, so a 1-3s reconnect is
// invisible to them. Past the deadline the socket is drained and closed
// cleanly (FIN, not RST) so the caller sees a plain connection close.
const BRIDGE_WAIT_FOR_CONN: Duration = Duration::from_secs(10);
// Sleep between failed reconnect attempts, doubling from 1s. Short on
// purpose: the sleep is cut even shorter by an app kick or by the home relay
// coming back (see wait_backoff), so it rarely matters — while a long cap was
// what made a reconnect trail service return by up to ~65s on real cellular
// (Galaxy S25, 2026-09-01: 108s from the drop, 65s after service was back).
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(10);
// The loopback listener is re-bound in place (same port) when it dies — iOS
// kills it during app suspension while the QUIC connection survives (iPhone
// X, 2026-09-01) — and on an app kick. The old socket is released when its
// accept task is aborted; a few short retries cover that window.
const REBIND_ATTEMPTS: u32 = 12;
const REBIND_DELAY: Duration = Duration::from_millis(250);
// Bounded native event ring the app drains into its diagnostics log.
const EVENT_RING_CAP: usize = 64;

// Graceful teardown: on stop/switch, let in-flight bridges finish before closing
// the connection, bounded so a long media stream can't hold the old endpoint open.
// Also caps endpoint.close() (see drain_and_close), so total background teardown is
// drain + close ≈ up to 2×DRAIN_TIMEOUT before the old UDP socket is released.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(3);
const DRAIN_POLL: Duration = Duration::from_millis(50);

// Loopback hop auth: every local TCP client must present `__lt=<local_token>` in
// the first HTTP request line (the app appends it to loopback URLs). The shim
// PEEKs (does not consume) the request line and drops connections without the
// token, so other apps on the device can't use 127.0.0.1:<port> as a proxy.
const LOCAL_TOKEN_PEEK_MAX: usize = 8 * 1024;
const LOCAL_TOKEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Tunnel status, shared with the C ABI / Dart (keep values in sync with
/// `lib/native/iroh_tunnel.dart`).
pub const STATUS_CONNECTING: u8 = 0;
pub const STATUS_CONNECTED: u8 = 1;
pub const STATUS_RECONNECTING: u8 = 2;
pub const STATUS_REJECTED: u8 = 3; // wrong/rotated secret — re-pair needed
pub const STATUS_DOWN: u8 = 4;

/// Selected-path kind, shared with the C ABI / Dart (`IrohPathKind`).
pub const PATH_UNKNOWN: u8 = 0;
pub const PATH_DIRECT: u8 = 1; // hole-punched direct path
pub const PATH_RELAY: u8 = 2; // routed via a relay server

/// State shared between the accept loop, the per-socket bridges, and the reconnect
/// supervisor. The live [`Connection`] is swapped in place on reconnect (it's a
/// cheap Arc handle to clone), so bridges always pick up the current one.
struct Shared {
    endpoint: Endpoint,
    /// Where to dial. Replaceable: a credential refresh may carry a newer
    /// ticket for the same server (its relay / direct addresses move).
    addr: Mutex<EndpointAddr>,
    alpn: &'static [u8],
    kind: PairingKind,
    /// What the first bi-stream carries — the connect secret, or a guest
    /// token. Replaceable in place, see [`Tunnel::set_credential`].
    payload: Mutex<Vec<u8>>,
    conn: Mutex<Connection>,
    status: AtomicU8,
    /// Same value as [`Shared::status`], as a watch channel so bridges can
    /// await the next status change instead of polling.
    status_tx: watch::Sender<u8>,
    /// In-flight TCP⇆bi-stream bridges, so teardown can drain them gracefully.
    active_bridges: AtomicUsize,
    /// Random per-tunnel token the local HTTP client must echo as `__lt=<token>`,
    /// so only this app (not other apps on the device) can use the loopback proxy.
    local_token: String,
    /// The loopback port, fixed for the tunnel's lifetime: the accept loop
    /// re-binds it in place when the listener dies, so the app's URLs stay valid.
    local_port: u16,
    /// The accept task, replaceable: a kick aborts it (dropping the listener)
    /// and spawns a fresh one on the same port.
    accept: Mutex<Option<JoinHandle<()>>>,
    /// The reconnect supervisor, replaceable too: it exits on a rejected
    /// handshake, and a credential refresh spawns a fresh one on the same
    /// port ([`Tunnel::set_credential`]).
    supervisor: Mutex<Option<JoinHandle<()>>>,
    /// App kicks as a generation counter: a kick bumps it, and a backoff wait
    /// ends early only when the generation moves past the value its attempt
    /// started with ([`kick_after`]). A `Notify` used to sit here; it stored a
    /// permit whenever a kick landed while nothing was backing off — the usual
    /// case, since the re-dial succeeds at once — and that stale permit cut the
    /// FIRST backoff of the next outage short with a spurious "app kick" event.
    kick_gen: watch::Sender<u64>,
    /// Native events for the app's diagnostics log (drained by the status poll).
    events: Mutex<EventRing>,
    started: Instant,
    /// Bridges that gave up waiting for a connection / were rejected at the
    /// loopback token check, reported in the drained events when they change.
    bridges_open_failed: AtomicU32,
    bridges_token_rejected: AtomicU32,
    reported_open_failed: AtomicU32,
    reported_token_rejected: AtomicU32,
}

/// Bounded ring of native events (newest last). `push` drops the oldest past
/// the cap and counts the drops so the app can see the ring overflowed.
struct EventRing {
    lines: VecDeque<String>,
    dropped: u32,
}

impl EventRing {
    fn new() -> Self {
        EventRing {
            lines: VecDeque::with_capacity(EVENT_RING_CAP),
            dropped: 0,
        }
    }
    fn push(&mut self, line: String) {
        if self.lines.len() >= EVENT_RING_CAP {
            self.lines.pop_front();
            self.dropped += 1;
        }
        self.lines.push_back(line);
    }
    /// Everything since the last drain, one event per line; None when empty.
    fn drain(&mut self) -> Option<String> {
        if self.lines.is_empty() {
            return None;
        }
        let mut out = String::new();
        if self.dropped > 0 {
            out.push_str(&format!("({} older events dropped)\n", self.dropped));
            self.dropped = 0;
        }
        for l in self.lines.drain(..) {
            out.push_str(&l);
            out.push('\n');
        }
        Some(out)
    }
}

impl Shared {
    fn set_status(&self, s: u8) {
        self.status.store(s, Ordering::Relaxed);
        let _ = self.status_tx.send_replace(s);
    }
    /// Record a native event (with seconds since bind) for the app's log and
    /// mirror it to the platform log (logcat on Android).
    fn event(&self, msg: impl AsRef<str>) {
        let line = format!("+{:.1}s {}", self.started.elapsed().as_secs_f32(), msg.as_ref());
        platform_log(PLATFORM_LOG_INFO, &line);
        if let Ok(mut ring) = self.events.lock() {
            ring.push(line);
        }
    }
    /// Whether any home relay is currently connected — the discriminator
    /// between "dead zone" (leave the supervisor alone) and "relay fine but the
    /// dial keeps failing" (worth a fresh endpoint) for the app's watchdog.
    fn relay_online(&self) -> bool {
        let mut w = self.endpoint.home_relay_status();
        w.get().iter().any(|r| r.is_connected())
    }
    /// Drain the events ring, appending the bridge counters when they moved.
    fn drain_events(&self) -> Option<String> {
        let mut out = self.events.lock().ok().and_then(|mut r| r.drain());
        let of = self.bridges_open_failed.load(Ordering::Relaxed);
        let tr = self.bridges_token_rejected.load(Ordering::Relaxed);
        if of != self.reported_open_failed.swap(of, Ordering::Relaxed)
            || tr != self.reported_token_rejected.swap(tr, Ordering::Relaxed)
        {
            let line = format!("bridges: open_failed={of} token_rejected={tr}\n");
            out = Some(out.unwrap_or_default() + &line);
        }
        out
    }
    fn current_conn(&self) -> Connection {
        self.conn.lock().unwrap().clone()
    }
    /// Record an app kick (or a credential swap that should be tried at once):
    /// a supervisor sleeping out a backoff, or failing the attempt in flight,
    /// retries immediately. Kicks older than the current attempt are spent.
    fn kick(&self) {
        self.kick_gen.send_modify(|g| *g += 1);
    }
    /// Classify the live connection's *selected* path: direct (hole-punched),
    /// relayed, or unknown (no path selected yet / not connected). A snapshot.
    fn path_kind(&self) -> u8 {
        if self.status.load(Ordering::Relaxed) != STATUS_CONNECTED {
            return PATH_UNKNOWN;
        }
        let conn = self.current_conn();
        for p in conn.paths().iter() {
            if p.is_selected() {
                return if p.is_relay() { PATH_RELAY } else { PATH_DIRECT };
            }
        }
        PATH_UNKNOWN
    }
}

pub(crate) const PLATFORM_LOG_INFO: i32 = 4; // ANDROID_LOG_INFO
#[cfg_attr(not(feature = "c-abi"), allow(dead_code))]
pub(crate) const PLATFORM_LOG_ERROR: i32 = 6; // ANDROID_LOG_ERROR

/// Mirror a line to the platform log (`adb logcat -s iroh_tunnel`). No-op
/// elsewhere; iOS reads these through the app's drained events instead.
#[cfg(target_os = "android")]
pub(crate) fn platform_log(prio: i32, msg: &str) {
    use std::ffi::{c_char, CString};
    #[link(name = "log")]
    extern "C" {
        fn __android_log_write(prio: i32, tag: *const c_char, text: *const c_char) -> i32;
    }
    if let (Ok(tag), Ok(text)) = (CString::new("iroh_tunnel"), CString::new(msg)) {
        unsafe { __android_log_write(prio, tag.as_ptr(), text.as_ptr()) };
    }
}
#[cfg(not(target_os = "android"))]
pub(crate) fn platform_log(_prio: i32, _msg: &str) {}

/// RAII counter for [`Shared::active_bridges`]: increments on creation and
/// decrements on drop, so teardown can wait for in-flight bridges to finish on
/// every exit path (clean EOF, error, early return, panic).
struct BridgeGuard<'a>(&'a Arc<Shared>);
impl<'a> BridgeGuard<'a> {
    fn new(shared: &'a Arc<Shared>) -> Self {
        shared.active_bridges.fetch_add(1, Ordering::Relaxed);
        BridgeGuard(shared)
    }
}
impl Drop for BridgeGuard<'_> {
    fn drop(&mut self) {
        self.0.active_bridges.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Bounded drain then graceful close: wait (up to [`DRAIN_TIMEOUT`]) for in-flight
/// bridges to finish, send a clean QUIC CONNECTION_CLOSE, then close the endpoint.
/// iroh's `endpoint.close()` retransmits the CONNECTION_CLOSE and can take ~3s on a
/// bad link, so we cap it too — a wedged close can't pin the old UDP socket open.
async fn drain_and_close(shared: Arc<Shared>) {
    let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
    while shared.active_bridges.load(Ordering::Relaxed) > 0
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(DRAIN_POLL).await;
    }
    shared.current_conn().close(0u32.into(), b"client shutdown");
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, shared.endpoint.close()).await;
}

/// A running tunnel. The loopback port is STABLE for the tunnel's lifetime (it
/// survives reconnects AND listener re-binds), so URLs the app builds against it
/// stay valid across a network blip / server restart / app suspension. Prefer
/// [`Tunnel::shutdown`]; `Drop` is a fallback.
pub struct Tunnel {
    /// Loopback port the app should treat as the server base URL.
    pub local_port: u16,
    shared: Arc<Shared>,
    /// Set by [`Tunnel::begin_shutdown`] so [`Drop`] doesn't slam the connection
    /// shut after a graceful, drained teardown was already scheduled.
    shutting_down: AtomicBool,
}

impl Tunnel {
    /// The base URL the tunnel serves the server at.
    pub fn local_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.local_port)
    }

    /// Current status (one of the `STATUS_*` constants).
    pub fn status(&self) -> u8 {
        self.shared.status.load(Ordering::Relaxed)
    }

    /// Current selected-path kind (one of the `PATH_*` constants).
    pub fn path_kind(&self) -> u8 {
        self.shared.path_kind()
    }

    /// The loopback auth token the local HTTP client must present (`__lt=<token>`).
    pub fn local_token(&self) -> String {
        self.shared.local_token.clone()
    }

    /// Whether any home relay is connected right now.
    pub fn relay_online(&self) -> bool {
        self.shared.relay_online()
    }

    /// Native events since the last call (one per line), or None when nothing
    /// happened. Drained by the app's status poll into its diagnostics log.
    pub fn drain_events(&self) -> Option<String> {
        self.shared.drain_events()
    }

    /// Fire-and-forget network nudge: tell iroh the network may have changed (Android
    /// can't self-detect) so it re-homes the relay + re-probes paths. Runs on `rt`
    /// and holds no lock during the re-probe — `tunnel_network_changed` is reached
    /// from the UI isolate, which also polls status and must not block.
    pub fn nudge_network(&self, rt: &tokio::runtime::Runtime) {
        let endpoint = self.shared.endpoint.clone();
        rt.spawn(async move {
            endpoint.network_change().await;
        });
    }

    /// Reconnect IN PLACE — same endpoint, same loopback port, same token — so
    /// nothing the app built against the tunnel goes stale: nudge iroh about
    /// the network, re-bind the loopback listener (iOS kills it during a
    /// suspension while the QUIC connection survives), then close the current
    /// connection so the supervisor wakes and re-dials at once, cutting any
    /// backoff sleep short. The app calls this after two failed liveness
    /// probes on a tunnel that still REPORTS connected; a hard stop/start is
    /// its fallback when this does not converge. Non-blocking (runs on `rt`).
    pub fn force_reconnect(&self, rt: &tokio::runtime::Runtime) {
        let shared = self.shared.clone();
        rt.spawn(async move {
            shared.event("app kick: network_change, listener re-bind, close");
            shared.endpoint.network_change().await;
            if !respawn_listener(&shared).await {
                // Port taken by something else: nothing in-place can fix that.
                shared.event("listener re-bind failed after kick — tunnel down");
                shared.set_status(STATUS_DOWN);
                return;
            }
            // No-op if the supervisor already saw this connection close.
            shared.current_conn().close(0u32.into(), b"app kick");
            shared.kick();
        });
    }

    /// Which kind of server this tunnel dials.
    pub fn kind(&self) -> PairingKind {
        self.shared.kind
    }

    /// Swap the credential (and the endpoint address) this tunnel dials with,
    /// IN PLACE — same loopback port, same token, so nothing the app built
    /// against the tunnel goes stale. A federated peer's guest token expires
    /// daily and the parent hands out a fresh one; without this the only way
    /// to use it was a stop/start that rotated the port and every queued URL.
    ///
    /// The new code must be the same kind as the running one and name the
    /// same server (endpoint id) — a refreshed ticket may carry new relay or
    /// direct addresses, which are taken. It applies at the next dial:
    ///   - CONNECTED: the authenticated connection is kept; the supervisor's
    ///     next re-dial uses the new credential;
    ///   - RECONNECTING / CONNECTING: the backoff is cut short (a dial already
    ///     in flight with the old credential that gets rejected retries once
    ///     with the new one, see [`supervise`]);
    ///   - REJECTED (the supervisor gave up): a fresh supervisor is spawned
    ///     and re-dials at once — the listener never left the port.
    ///
    /// Non-blocking: parsing is pure and the re-dial runs on `rt`.
    pub fn set_credential(&self, code: &str, rt: &tokio::runtime::Runtime) -> Result<()> {
        let pairing = parse_pairing_code(code)?;
        if pairing.kind != self.shared.kind {
            bail!(
                "credential kind mismatch: this tunnel is {:?}, the new code is {:?}",
                self.shared.kind,
                pairing.kind
            );
        }
        let ticket = EndpointTicket::decode_string(&pairing.ticket)
            .map_err(|e| anyhow!("invalid endpoint ticket: {e}"))?;
        let addr = ticket.endpoint_addr().clone();
        if addr.id != self.shared.addr.lock().unwrap().id {
            bail!("the new credential is for a different server (endpoint id changed)");
        }
        *self.shared.addr.lock().unwrap() = addr;
        *self.shared.payload.lock().unwrap() = pairing.payload;

        let shared = self.shared.clone();
        match shared.status.load(Ordering::Relaxed) {
            STATUS_REJECTED => {
                // The supervisor returned. A new one starts by awaiting the
                // (already closed) connection's close, which returns at once,
                // so it re-dials immediately with the new credential.
                shared.event("credential updated after a rejected handshake — re-dialing");
                shared.set_status(STATUS_RECONNECTING);
                let h = rt.spawn(supervise(shared.clone()));
                if let Some(old) = shared.supervisor.lock().unwrap().replace(h) {
                    old.abort();
                }
            }
            STATUS_RECONNECTING | STATUS_CONNECTING => {
                shared.event("credential updated — cutting the backoff short");
                shared.kick();
            }
            STATUS_DOWN => {
                shared.event("credential updated, but the tunnel is down (listener lost) — a restart is needed");
            }
            _ => {
                shared.event("credential updated — applies at the next dial");
            }
        }
        Ok(())
    }

    /// Begin a graceful, NON-BLOCKING teardown: stop accepting + supervising, then on
    /// `rt` run [`drain_and_close`] (drain in-flight bridges, then close conn +
    /// endpoint — see it for the bounded teardown window). The app calls stop()
    /// synchronously on the UI isolate, so this must return promptly — hence the
    /// work runs on the runtime instead of blocking the caller.
    pub fn begin_shutdown(self, rt: &tokio::runtime::Runtime) {
        if let Some(h) = self.shared.accept.lock().unwrap().take() {
            h.abort();
        }
        if let Some(h) = self.shared.supervisor.lock().unwrap().take() {
            h.abort();
        }
        // Suppress the immediate-close Drop; the spawned drain owns the close now.
        self.shutting_down.store(true, Ordering::Relaxed);
        rt.spawn(drain_and_close(self.shared.clone()));
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // A graceful, drained teardown was already scheduled by begin_shutdown.
        if self.shutting_down.load(Ordering::Relaxed) {
            return;
        }
        if let Ok(mut guard) = self.shared.accept.lock() {
            if let Some(h) = guard.take() {
                h.abort();
            }
        }
        if let Ok(mut guard) = self.shared.supervisor.lock() {
            if let Some(h) = guard.take() {
                h.abort();
            }
        }
        // Closing the connection makes in-flight bridge streams error out promptly.
        if let Ok(conn) = self.shared.conn.lock() {
            conn.close(0u32.into(), b"client dropped");
        }
        // endpoint.close() is async and Drop can't await; best-effort drain.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let endpoint = self.shared.endpoint.clone();
            handle.spawn(async move { endpoint.close().await });
        }
    }
}

/// Outcome of a dial + secret handshake.
enum DialResult {
    Connected(Connection),
    Rejected,       // server said "NO" → wrong/rotated secret
    Failed(String), // transient: unreachable / timeout / mid-handshake error, with why
}

/// A connection close whose reason says the credential was refused.
fn is_refusal(error: &str) -> bool {
    let e = error.to_ascii_lowercase();
    ["unauthorized", "backoff", "revoked"].iter().any(|word| e.contains(word))
}

/// Connect on `alpn` and run the handshake on the first bi-stream: write the
/// credential (the 32-byte connect secret, or a guest token), expect "OK".
async fn dial_and_handshake(
    endpoint: &Endpoint,
    addr: &EndpointAddr,
    alpn: &[u8],
    payload: &[u8],
) -> DialResult {
    match dial(endpoint, addr, alpn).await {
        Ok(conn) => handshake(conn, payload).await,
        Err(why) => DialResult::Failed(why),
    }
}

/// The QUIC connection, bounded.
async fn dial(endpoint: &Endpoint, addr: &EndpointAddr, alpn: &[u8]) -> Result<Connection, String> {
    match tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(addr.clone(), alpn)).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(e)) => Err(format!("connect error: {e}")),
        Err(_) => Err(format!("connect timed out after {}s", CONNECT_TIMEOUT.as_secs())),
    }
}

/// The credential on the first bi-stream, bounded so a stalled or half-dead
/// server cannot park the supervisor.
async fn handshake(conn: Connection, payload: &[u8]) -> DialResult {
    let probe = conn.clone(); // the block below owns `conn`; the stall report reads the path off this
    let attempt = async {
        let (mut send, mut recv) = match conn.open_bi().await {
            Ok(pair) => pair,
            Err(e) => return DialResult::Failed(format!("open_bi: {e}")),
        };
        if send.write_all(payload).await.is_err() || send.finish().is_err() {
            return DialResult::Failed("handshake write failed".into());
        }
        match recv.read_to_end(HANDSHAKE_RESP_LIMIT).await {
            Ok(resp) if resp == b"OK" => DialResult::Connected(conn),
            Ok(resp) if resp == b"NO" => DialResult::Rejected,
            // Empty / unexpected reply (truncation, a non-conforming server) is
            // transient — retry rather than declaring a permanent "re-pair".
            Ok(resp) => DialResult::Failed(format!("unexpected handshake reply ({} bytes)", resp.len())),
            // The server may also refuse by closing the connection with a
            // reason instead of answering (mStream's federation endpoint
            // does: "unauthorized", "backoff", "revoked") — a refusal all
            // the same, not a network that went away.
            Err(e) if is_refusal(&e.to_string()) => DialResult::Rejected,
            Err(e) => DialResult::Failed(format!("handshake read: {e}")),
        }
    };
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, attempt).await {
        Ok(result) => result,
        Err(_) => {
            // Transient. Say which path the connection sat on while the server
            // stayed silent (mStream#940): a fresh server endpoint stalls a
            // phone's first dials and the path is the first thing to know.
            let path = probe
                .paths()
                .iter()
                .find(|p| p.is_selected())
                .map(|p| if p.is_relay() { "relay" } else { "direct" })
                .unwrap_or("none");
            DialResult::Failed(format!("handshake stalled on {path} path"))
        }
    }
}

/// Watches the live connection and, when it dies, re-dials on the SAME endpoint
/// (reusing the warmed relay + discovered addrs) and swaps in the new connection —
/// so a network change / server restart recovers without the app re-pairing and
/// without the loopback port changing. Exits only on a rejected handshake.
///
/// Between failed attempts it sleeps a short, doubling backoff that is cut
/// short by an app kick or by the home relay coming back ([`wait_backoff`]),
/// so an attempt that overlapped service returning costs at most one more
/// dial, not a timer's worth of silence. Every attempt is recorded in the
/// events ring with its elapsed time, relay state and failure reason.
async fn supervise(shared: Arc<Shared>) {
    loop {
        // Park until the current connection closes for any reason.
        let why = shared.current_conn().closed().await;
        shared.set_status(STATUS_RECONNECTING);
        shared.event(format!("conn closed: {why}"));

        let mut backoff = Duration::from_secs(1);
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let t0 = Instant::now();
            // Kicks from here on — during this attempt or the backoff after it
            // — cut that backoff short; anything older is already spent.
            let kick_seen = *shared.kick_gen.borrow();
            // Re-warm a relay path before re-dialing (cheap if already online).
            let relay_online = tokio::time::timeout(ONLINE_TIMEOUT, shared.endpoint.online())
                .await
                .is_ok();
            // Snapshot the credential per attempt: set_credential may swap it
            // (and the address) while this dial is in flight.
            let addr = shared.addr.lock().unwrap().clone();
            let payload = shared.payload.lock().unwrap().clone();
            match dial_and_handshake(&shared.endpoint, &addr, shared.alpn, &payload).await {
                DialResult::Connected(c) => {
                    *shared.conn.lock().unwrap() = c;
                    shared.set_status(STATUS_CONNECTED);
                    shared.event(format!(
                        "reconnected: attempt {attempt} in {:.1}s relay_online={relay_online}",
                        t0.elapsed().as_secs_f32()
                    ));
                    break; // resume watching the new connection
                }
                DialResult::Rejected => {
                    // A credential swapped in while this dial was in flight
                    // deserves one more try before giving up.
                    if *shared.payload.lock().unwrap() != payload {
                        shared.event("handshake rejected with a stale credential — retrying with the new one");
                        continue;
                    }
                    shared.set_status(STATUS_REJECTED);
                    shared.event(match shared.kind {
                        PairingKind::Tunnel => "handshake rejected — re-pair needed",
                        PairingKind::FederationGuest => {
                            "handshake rejected — guest token refused (expired or revoked); refresh it from the parent"
                        }
                    });
                    return; // the app must re-pair (or, for a guest, refresh the token)
                }
                DialResult::Failed(reason) => {
                    shared.event(format!(
                        "attempt {attempt} failed after {:.1}s relay_online={relay_online}: {reason}; backoff {}s",
                        t0.elapsed().as_secs_f32(),
                        backoff.as_secs()
                    ));
                    let woke = wait_backoff(&shared, backoff, kick_seen).await;
                    backoff = next_backoff(backoff, woke);
                }
            }
        }
    }
}

/// The backoff after a failed attempt: back to 1s when something woke us
/// (the relay came back, the app kicked) — the next dial is likely to work —
/// else doubled and capped. Pure; unit-tested.
fn next_backoff(prev: Duration, woke: bool) -> Duration {
    if woke {
        Duration::from_secs(1)
    } else {
        (prev * 2).min(RECONNECT_BACKOFF_MAX)
    }
}

/// Resolves once the kick generation has moved past `seen`: at once when it
/// already has (a kick that landed during the attempt), else on the next kick.
/// Never resolves for kicks older than `seen`. Unit-tested.
async fn kick_after(kick_gen: &watch::Sender<u64>, seen: u64) {
    let mut rx = kick_gen.subscribe();
    // wait_for tests the current value first, even one already marked seen.
    if rx.wait_for(|g| *g != seen).await.is_err() {
        // The sender lives in Shared, so this cannot happen while a supervisor
        // runs; if it ever did, no kick can come and the sleep should win.
        std::future::pending::<()>().await;
    }
}

/// Sleep `backoff`, returning early (true) on an app kick newer than
/// `kick_seen` or on the home relay going from down to up. Only a DOWN→UP
/// relay edge counts: a relay that was already up when the attempt failed says
/// nothing about the next attempt.
async fn wait_backoff(shared: &Shared, backoff: Duration, kick_seen: u64) -> bool {
    let mut relay = shared.endpoint.home_relay_status();
    let relay_was_up = relay.get().iter().any(|r| r.is_connected());
    let relay_back = async {
        if relay_was_up {
            std::future::pending::<()>().await;
        }
        loop {
            match relay.updated().await {
                Ok(v) if v.iter().any(|r| r.is_connected()) => return,
                Ok(_) => continue,
                Err(_) => std::future::pending::<()>().await,
            }
        }
    };
    tokio::select! {
        _ = tokio::time::sleep(backoff) => false,
        _ = kick_after(&shared.kick_gen, kick_seen) => {
            shared.event("backoff cut short: app kick");
            true
        }
        _ = relay_back => {
            shared.event("backoff cut short: home relay back");
            true
        }
    }
}

/// Why a dial did not end in a serving tunnel. The `Display` text is what the
/// C ABI's `last_error` and the dev CLI print, and it keeps the words the
/// bindings match on: a refused credential says "rejected".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialError {
    /// The credential is not a code this client understands, or is malformed.
    BadCode(String),
    /// The server refused the credential: a wrong or rotated connect secret,
    /// or an expired or revoked guest token. Re-dialling the same code will
    /// not help; a new one might.
    Rejected { kind: PairingKind },
    /// The server could not be reached, or never answered the handshake —
    /// worth retrying. `relay_online` says whether this machine reached the
    /// iroh relay network at all, which points the blame one way or the other.
    Unreachable { reason: String, relay_online: bool, elapsed: Duration },
    /// A failure on this side: the endpoint or the loopback port would not bind.
    Local(String),
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialError::BadCode(why) => write!(f, "{why}"),
            DialError::Rejected { kind: PairingKind::Tunnel } => write!(
                f,
                "tunnel handshake rejected — wrong or rotated connect secret; re-pair from the server's Remote Access panel"
            ),
            DialError::Rejected { kind: PairingKind::FederationGuest } => write!(
                f,
                "handshake rejected — the guest token was refused (expired or revoked); refresh it from the parent server"
            ),
            DialError::Unreachable { reason, relay_online, elapsed } => write!(
                f,
                "could not reach the server through the tunnel ({reason}; home relay {}; {:.1}s) — it may be offline or the pairing code is stale",
                if *relay_online { "online" } else { "not reached" },
                elapsed.as_secs_f32()
            ),
            DialError::Local(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for DialError {}

impl DialError {
    /// The server said no to the credential itself, as opposed to not
    /// answering: the one failure a re-dial with the same code cannot fix.
    pub fn is_rejected(&self) -> bool {
        matches!(self, DialError::Rejected { .. })
    }
}

/// What a code says before anything is dialled: the kind of server it reaches
/// and that server's iroh endpoint id (a public key — the stable identity a
/// client can file the server under, whatever port or network the tunnel
/// lands on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub kind: PairingKind,
    pub endpoint_id: String,
}

/// Parse a code for what it names, without dialling.
pub fn inspect(code: &str) -> Result<Credential, DialError> {
    let pairing = parse_pairing_code(code)?;
    let ticket = EndpointTicket::decode_string(&pairing.ticket)
        .map_err(|e| DialError::BadCode(format!("invalid endpoint ticket: {e}")))?;
    Ok(Credential { kind: pairing.kind, endpoint_id: ticket.endpoint_addr().id.to_string() })
}

/// The steps of a dial, in order, as [`connect_tunnel_staged`] reports them —
/// so a diagnostic can say which one a hostile network killed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    /// The local iroh endpoint is bound.
    Bound,
    /// The wait for a home relay ended: reached (with its URL) or not, in
    /// which case the dial goes on over direct addresses anyway.
    Relay { online: bool, url: Option<String> },
    /// The server accepted the QUIC connection.
    Connected,
    /// The server accepted the credential.
    Handshaken,
    /// The loopback bridge is listening; the tunnel is ready to serve.
    Serving { local_port: u16 },
}

/// Which kind of server a code dials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingKind {
    /// Quick Connect: `mstr<V>:{t,s}` — the 32-byte connect secret, ALPN
    /// `mstream/tunnel/2`.
    Tunnel,
    /// A federated peer, dialed directly: `mstrfedg<V>:{t,g}` — a guest token
    /// the parent server fetched for this device, ALPN `mstream/federation/1`
    /// (mStream `docs/federation-guest-ticket.md`).
    FederationGuest,
}

/// What a code resolves to: where to dial, on which ALPN, and what to write
/// on the first bi-stream.
#[derive(Debug)]
struct Pairing {
    ticket: String,
    alpn: &'static [u8],
    payload: Vec<u8>,
    kind: PairingKind,
}

/// Decode base64 tolerantly — accepts both the standard and URL-safe alphabets,
/// padded or not. Node's `Buffer.from(x, 'base64'|'base64url')` is equally lenient,
/// so this keeps us interoperable with whatever the server emits.
fn b64_loose(s: &str) -> Result<Vec<u8>> {
    let norm: String = s
        .chars()
        .filter_map(|c| match c {
            '-' => Some('+'),
            '_' => Some('/'),
            '=' => None,
            c if c.is_whitespace() => None,
            c => Some(c),
        })
        .collect();
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(norm)
        .map_err(|e| anyhow!("invalid base64: {e}"))
}

/// Split `<prefix><digits>:<body>`; None when the prefix or a numeric version
/// is absent (then the string is not this envelope).
fn split_envelope<'a>(s: &'a str, prefix: &str) -> Option<(u32, &'a str)> {
    let rest = s.strip_prefix(prefix)?;
    let (ver, body) = rest.split_once(':')?;
    if ver.is_empty() || !ver.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((ver.parse::<u32>().unwrap_or(u32::MAX), body))
}

fn decode_body(body: &str, label: &str) -> Result<serde_json::Value> {
    let json = b64_loose(body).with_context(|| format!("invalid {label} (not base64)"))?;
    serde_json::from_slice(&json).with_context(|| format!("invalid {label} (not JSON)"))
}

fn field_str(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

/// Parse a code into where to dial and what to present. Two envelopes:
///
///   * Quick Connect pairing code (docs/iroh-pairing-code.md in mStream PR
///     #643): `mstr<V>:<base64url(JSON{t,s})>`; a bare (un-prefixed) body is a
///     legacy code → implicit v1. `s` is the 32-byte connect secret.
///   * Federation guest ticket (mStream docs/federation-guest-ticket.md):
///     `mstrfedg<V>:<base64url(JSON{t,g})>`; `g` is the guest token, written
///     as-is on the first bi-stream of the federation ALPN. No bare form.
///
/// A federation TICKET (`mstrfed<V>:`, the admin-to-admin pairing that carries
/// a standing key) is refused by name — the app must never hold one. A version
/// newer than this client understands is rejected with an actionable "update
/// the app" error. Pure (no native module).
fn parse_pairing_code(code: &str) -> Result<Pairing, DialError> {
    let trimmed = code.trim();

    // The guest envelope first: its prefix extends the tunnel one, and the
    // tunnel branch would otherwise read `fedg1` as a missing version.
    if let Some((version, body)) = split_envelope(trimmed, "mstrfedg") {
        if version > GUEST_TICKET_VERSION {
            return Err(DialError::BadCode(format!(
                "Guest ticket is version {version}; this app supports up to v{GUEST_TICKET_VERSION}. Update to a newer version of the app."
            )));
        }
        let v = decode_body(body, "guest ticket").map_err(bad_code)?;
        let ticket =
            field_str(&v, "t").ok_or_else(|| DialError::BadCode("invalid guest ticket (missing ticket)".to_string()))?;
        let token =
            field_str(&v, "g").ok_or_else(|| DialError::BadCode("invalid guest ticket (missing token)".to_string()))?;
        if token.is_empty() || token.len() > GUEST_TOKEN_MAX {
            return Err(DialError::BadCode(format!("invalid guest ticket (token length {})", token.len())));
        }
        return Ok(Pairing {
            ticket,
            alpn: FEDERATION_ALPN,
            payload: token.into_bytes(),
            kind: PairingKind::FederationGuest,
        });
    }
    if split_envelope(trimmed, "mstrfed").is_some() {
        return Err(DialError::BadCode(
            "This is a federation ticket for pairing two servers, not a pairing code for the app.".to_string()
            ));
    }

    let (version, body) = split_envelope(trimmed, "mstr").unwrap_or((1, trimmed));
    if version > PAIRING_VERSION {
        return Err(DialError::BadCode(format!(
            "Pairing code is version {version}; this app supports up to v{PAIRING_VERSION}. Update to a newer version of the app."
        )));
    }
    let v = decode_body(body, "pairing code").map_err(bad_code)?;
    let ticket =
        field_str(&v, "t").ok_or_else(|| DialError::BadCode("invalid pairing code (missing ticket)".to_string()))?;
    let secret_b64 =
        field_str(&v, "s").ok_or_else(|| DialError::BadCode("invalid pairing code (missing secret)".to_string()))?;
    let secret = b64_loose(&secret_b64)
        .map_err(|e| DialError::BadCode(format!("invalid pairing code (bad secret): {e}")))?;
    if secret.len() != SECRET_LEN {
        return Err(DialError::BadCode(format!("connect secret must be {SECRET_LEN} bytes (got {})", secret.len())));
    }
    Ok(Pairing {
        ticket,
        alpn: TUNNEL_ALPN,
        payload: secret,
        kind: PairingKind::Tunnel,
    })
}

fn bad_code(e: anyhow::Error) -> DialError {
    DialError::BadCode(format!("{e:#}"))
}

/// Bind the local iroh endpoint. With the `os-trust` feature the relay's TLS
/// is checked against what the operating system trusts, not only the
/// compiled-in roots — a corporate network that inspects TLS re-signs the
/// relay with a CA only the system store knows. The environment's proxy is
/// honoured either way, for a network that drops direct dials on the floor.
async fn bind_endpoint() -> Result<Endpoint, DialError> {
    let builder = Endpoint::builder(presets::N0).proxy_from_env();
    #[cfg(feature = "os-trust")]
    let builder = builder.ca_tls_config(iroh::tls::CaTlsConfig::system());
    builder
        .bind()
        .await
        .map_err(|e| DialError::Local(format!("failed to bind iroh endpoint: {e}")))
}

/// The home relay this endpoint is on, if it has one yet.
fn home_relay_url(endpoint: &Endpoint) -> Option<String> {
    endpoint.addr().addrs.into_iter().find_map(|addr| match addr {
        TransportAddr::Relay(url) => Some(url.to_string()),
        _ => None,
    })
}

/// Dial a tunnel from a pairing code, complete the secret handshake, and start a
/// loopback TCP proxy with a reconnect supervisor. Returns once it's ready to serve.
/// `local_port` of 0 picks an ephemeral port (the chosen port is in [`Tunnel`]).
pub async fn connect_tunnel(code: &str, local_port: u16) -> Result<Tunnel, DialError> {
    connect_tunnel_staged(code, local_port, &mut |_| {}).await
}

/// [`connect_tunnel`], reporting each [`Stage`] as it completes — for a
/// diagnostic that has to say which step a hostile network killed.
pub async fn connect_tunnel_staged(
    code: &str,
    local_port: u16,
    on_stage: &mut dyn FnMut(Stage),
) -> Result<Tunnel, DialError> {
    let pairing = parse_pairing_code(code)?;
    let ticket = EndpointTicket::decode_string(&pairing.ticket)
        .map_err(|e| DialError::BadCode(format!("invalid endpoint ticket: {e}")))?;
    let addr = ticket.endpoint_addr().clone();

    let endpoint = bind_endpoint().await?;
    on_stage(Stage::Bound);

    // Cross-network: establish our own home relay BEFORE dialing, else the first
    // stream can reset on a not-ready path. Bounded; proceed even if it times out.
    let online = tokio::time::timeout(ONLINE_TIMEOUT, endpoint.online()).await.is_ok();
    on_stage(Stage::Relay { online, url: home_relay_url(&endpoint) });

    // First dial + handshake; distinguish a rejected secret for a clear error.
    // The failure reason and relay state ride along: "may be offline" used to
    // hide "no home relay within 8s; connect timed out after 25s".
    let t0 = Instant::now();
    let unreachable = |reason: String, endpoint: &Endpoint| DialError::Unreachable {
        reason,
        relay_online: endpoint.home_relay_status().get().iter().any(|r| r.is_connected()),
        elapsed: t0.elapsed(),
    };
    let conn = match dial(&endpoint, &addr, pairing.alpn).await {
        Ok(conn) => conn,
        Err(reason) => return Err(unreachable(reason, &endpoint)),
    };
    on_stage(Stage::Connected);
    let conn = match handshake(conn, &pairing.payload).await {
        DialResult::Connected(c) => c,
        DialResult::Rejected => return Err(DialError::Rejected { kind: pairing.kind }),
        DialResult::Failed(reason) => return Err(unreachable(reason, &endpoint)),
    };
    on_stage(Stage::Handshaken);

    let listener = TcpListener::bind(("127.0.0.1", local_port))
        .await
        .map_err(|e| DialError::Local(format!("failed to bind local proxy port: {e}")))?;
    let bound_port = listener
        .local_addr()
        .map_err(|e| DialError::Local(format!("failed to read the local proxy port: {e}")))?
        .port();

    let (status_tx, _status_rx) = watch::channel(STATUS_CONNECTED);
    let path = {
        let mut kind = "unknown";
        for p in conn.paths().iter() {
            if p.is_selected() {
                kind = if p.is_relay() { "relay" } else { "direct" };
            }
        }
        kind
    };
    let mode = match pairing.kind {
        PairingKind::Tunnel => "tunnel",
        PairingKind::FederationGuest => "guest",
    };
    let shared = Arc::new(Shared {
        endpoint,
        addr: Mutex::new(addr),
        alpn: pairing.alpn,
        kind: pairing.kind,
        payload: Mutex::new(pairing.payload),
        conn: Mutex::new(conn),
        status: AtomicU8::new(STATUS_CONNECTED),
        status_tx,
        active_bridges: AtomicUsize::new(0),
        local_token: gen_local_token().map_err(|e| DialError::Local(format!("{e:#}")))?,
        local_port: bound_port,
        accept: Mutex::new(None),
        supervisor: Mutex::new(None),
        kick_gen: watch::channel(0u64).0,
        events: Mutex::new(EventRing::new()),
        started: Instant::now(),
        bridges_open_failed: AtomicU32::new(0),
        bridges_token_rejected: AtomicU32::new(0),
        reported_open_failed: AtomicU32::new(0),
        reported_token_rejected: AtomicU32::new(0),
    });
    shared.event(format!(
        "bound 127.0.0.1:{bound_port}, first dial OK in {:.1}s path={path} mode={mode}",
        t0.elapsed().as_secs_f32()
    ));

    let accept = tokio::spawn(serve_loopback(shared.clone(), listener));
    *shared.accept.lock().unwrap() = Some(accept);

    let supervisor = tokio::spawn(supervise(shared.clone()));
    *shared.supervisor.lock().unwrap() = Some(supervisor);
    on_stage(Stage::Serving { local_port: bound_port });

    Ok(Tunnel {
        local_port: bound_port,
        shared,
        shutting_down: AtomicBool::new(false),
    })
}

/// The loopback accept loop. A failed accept used to end it silently while
/// the status kept saying connected — that is how an iOS suspension (which
/// kills the listener socket but not the QUIC connection) left every local
/// request refused. Now it re-binds the SAME port in place and carries on;
/// only a port that cannot be re-bound takes the tunnel down.
async fn serve_loopback(shared: Arc<Shared>, mut listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((sock, _)) => {
                let s = shared.clone();
                tokio::spawn(async move { bridge_socket(sock, s).await });
            }
            Err(e) => {
                shared.event(format!(
                    "accept failed: {e} — re-binding 127.0.0.1:{}",
                    shared.local_port
                ));
                match rebind_listener(&shared).await {
                    Some(l) => {
                        listener = l;
                        shared.event("listener re-bound");
                    }
                    None => {
                        shared.event("listener re-bind failed — tunnel down");
                        shared.set_status(STATUS_DOWN);
                        return;
                    }
                }
            }
        }
    }
}

/// Bind the tunnel's loopback port again, retrying briefly while a dying
/// socket still holds it.
async fn rebind_listener(shared: &Shared) -> Option<TcpListener> {
    for _ in 0..REBIND_ATTEMPTS {
        match TcpListener::bind(("127.0.0.1", shared.local_port)).await {
            Ok(l) => return Some(l),
            Err(_) => tokio::time::sleep(REBIND_DELAY).await,
        }
    }
    None
}

/// Replace the accept task with a fresh listener on the same port (the kick
/// path). True when the port was re-bound.
async fn respawn_listener(shared: &Arc<Shared>) -> bool {
    if let Some(h) = shared.accept.lock().unwrap().take() {
        h.abort(); // drops the old listener, releasing the port
    }
    match rebind_listener(shared).await {
        Some(l) => {
            let h = tokio::spawn(serve_loopback(shared.clone(), l));
            *shared.accept.lock().unwrap() = Some(h);
            shared.event("listener re-bound");
            true
        }
        None => false,
    }
}

/// Generate a random 128-bit loopback token, hex-encoded (32 chars).
fn gen_local_token() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|e| anyhow!("rng failure: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Authenticate the LOCAL hop: peek (WITHOUT consuming) the first HTTP request
/// line and require `__lt=<local_token>` in it. Returns false (→ drop the socket)
/// for any client that doesn't present the token — i.e. another app on the device.
/// Peeking (not reading) means the request bytes are still delivered to the server
/// untouched, and validating once per connection is keep-alive-safe.
async fn local_token_ok(sock: &TcpStream, token: &str) -> bool {
    let needle = format!("__lt={token}");
    let needle = needle.as_bytes();
    let mut buf = vec![0u8; LOCAL_TOKEN_PEEK_MAX];
    let deadline = tokio::time::Instant::now() + LOCAL_TOKEN_TIMEOUT;
    loop {
        let n = match tokio::time::timeout_at(deadline, sock.peek(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return false,
        };
        let head = &buf[..n];
        if let Some(pos) = head.windows(2).position(|w| w == b"\r\n") {
            return head[..pos].windows(needle.len()).any(|w| w == needle);
        }
        if n >= LOCAL_TOKEN_PEEK_MAX {
            return false; // request line too long / not HTTP
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// One inbound TCP connection ⇆ one fresh iroh bi-stream (full duplex).
///
/// Mirrors the reference `bridge()`/`dispose()`: each direction ends cleanly on
/// EOF (finish/shutdown), but if either direction *errors* we cancel the partner
/// so a half-open stream can't park.
async fn bridge_socket(sock: TcpStream, shared: Arc<Shared>) {
    // Count this bridge as in-flight for its whole lifetime (drops on every exit
    // path), so a graceful teardown can wait for it before closing the connection.
    let _bridge = BridgeGuard::new(&shared);
    // Authenticate the local hop first: only our app knows the token, so other apps
    // on the device that connect to 127.0.0.1:<port> are dropped before any bi-stream.
    if !local_token_ok(&sock, &shared.local_token).await {
        shared.bridges_token_rejected.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // Open a bi-stream on the CURRENT connection. While the supervisor is
    // mid-reconnect, wait (bounded) for the swapped-in connection rather than
    // hard-failing, so a request landing inside a 1-3s reconnect rides it.
    let mut rx = shared.status_tx.subscribe();
    let deadline = Instant::now() + BRIDGE_WAIT_FOR_CONN;
    let (send, recv) = loop {
        if shared.status.load(Ordering::Relaxed) == STATUS_CONNECTED {
            if let Ok(pair) = shared.current_conn().open_bi().await {
                break pair;
            }
            // The connection died between the status read and open_bi: fall
            // through and wait for the supervisor's swap.
        }
        tokio::select! {
            r = rx.changed() => {
                if r.is_err() {
                    return;
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                shared.bridges_open_failed.fetch_add(1, Ordering::Relaxed);
                // Consume what the client sent so the drop is a clean FIN, not
                // an RST with unread bytes.
                let mut sink = vec![0u8; 8192];
                let _ = tokio::time::timeout(Duration::from_millis(50), sock.readable()).await;
                let _ = sock.try_read(&mut sink);
                return;
            }
        }
    };
    let _ = sock.set_nodelay(true);
    let (r, w) = sock.into_split();
    let mut up = tokio::spawn(pump_reader_to_send(r, send));
    let mut down = tokio::spawn(pump_recv_to_writer(recv, w));

    // `false` == that direction errored → tear down the sibling (aborting the task
    // drops its stream half, which sends RESET/STOP). `true`/clean → let the other
    // direction finish (an HTTP request finishes long before its response).
    tokio::select! {
        res = &mut up => { if matches!(res, Ok(false)) { down.abort(); } else { let _ = down.await; } }
        res = &mut down => { if matches!(res, Ok(false)) { up.abort(); } else { let _ = up.await; } }
    }
}

/// TCP → iroh send stream. Returns `true` on clean EOF, `false` on error.
async fn pump_reader_to_send(mut r: OwnedReadHalf, mut send: SendStream) -> bool {
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        match r.read(&mut buf).await {
            Ok(0) => {
                let _ = send.finish();
                return true;
            }
            Ok(n) => {
                if send.write_all(&buf[..n]).await.is_err() {
                    let _ = send.reset(0u32.into());
                    return false;
                }
            }
            Err(_) => {
                let _ = send.reset(0u32.into());
                return false;
            }
        }
    }
}

/// iroh recv stream → TCP. Returns `true` on clean EOF, `false` on error.
async fn pump_recv_to_writer(mut recv: RecvStream, mut w: OwnedWriteHalf) -> bool {
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                if w.write_all(&buf[..n]).await.is_err() {
                    let _ = recv.stop(0u32.into());
                    return false;
                }
            }
            Ok(None) => {
                let _ = w.shutdown().await;
                return true;
            }
            Err(_) => {
                let _ = recv.stop(0u32.into());
                return false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    // A real ticket captured from a running mStream tunnel: what `inspect`
    // decodes for the endpoint id (the parse itself keeps the string whole).
    const REAL_TICKET: &str = "endpointabrraywtjw6g3m7gofwzvgif4t7p7b7olzxcske4lei7axhn53gmkbaaenuhi5dqom5c6l3vonstcljrfzzgk3dbpexg4mbonfzg62bonruw42zof4aqasj432dpvxydaeakyhaaah5n6aybadakqakh7lpqg";

    /// Stand up an endpoint speaking the server half of the tunnel protocol,
    /// as mStream implements it — the first bi-stream carries the secret and
    /// is answered OK (or NO), every later one is one TCP connection's worth
    /// of bytes to a local HTTP port that always answers `http_response` —
    /// and hand back its ticket. Relay-free, dialled by direct addresses: the
    /// test needs no network beyond this machine.
    fn fake_mstream_endpoint(
        rt: &tokio::runtime::Runtime,
        secret: [u8; SECRET_LEN],
        http_response: &'static [u8],
    ) -> String {
        let http = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http");
        let http_port = http.local_addr().expect("http addr").port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            while let Ok((mut sock, _)) = http.accept() {
                let mut head = Vec::new();
                let mut byte = [0u8; 256];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut byte) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&byte[..n]),
                    }
                }
                let _ = sock.write_all(http_response);
            }
        });

        let addr = rt.block_on(async move {
            let endpoint = Endpoint::builder(presets::Minimal)
                .alpns(vec![TUNNEL_ALPN.to_vec()])
                .bind()
                .await
                .expect("bind server endpoint");
            let addr = endpoint.addr();
            tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let Ok(connection) = incoming.await else { continue };
                    tokio::spawn(async move {
                        let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                            return;
                        };
                        let got = recv.read_to_end(256).await.unwrap_or_default();
                        if got != secret {
                            // As the server does: the verdict, then the
                            // connection closed with a reason.
                            let _ = send.write_all(b"NO").await;
                            let _ = send.finish();
                            let _ = send.stopped().await;
                            connection.close(0u32.into(), b"unauthorized");
                            return;
                        }
                        let _ = send.write_all(b"OK").await;
                        let _ = send.finish();
                        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                            tokio::spawn(async move {
                                let Ok(tcp) =
                                    tokio::net::TcpStream::connect(("127.0.0.1", http_port)).await
                                else {
                                    return;
                                };
                                let (mut tcp_read, mut tcp_write) = tcp.into_split();
                                let up = async {
                                    let _ = tokio::io::copy(&mut recv, &mut tcp_write).await;
                                };
                                let down = async {
                                    let _ = tokio::io::copy(&mut tcp_read, &mut send).await;
                                    let _ = send.finish();
                                };
                                tokio::join!(up, down);
                            });
                        }
                    });
                }
            });
            addr
        });
        EndpointTicket::from(addr).to_string()
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime")
    }

    #[test]
    fn inspect_names_the_server_without_dialling() {
        let code = format!("mstr1:{}", body(REAL_TICKET, &[9u8; SECRET_LEN]));
        let cred = inspect(&code).expect("inspect");
        assert_eq!(cred.kind, PairingKind::Tunnel);
        assert!(cred.endpoint_id.len() > 40, "an endpoint id is a public key: {}", cred.endpoint_id);
        // The same server, a new secret: the identity holds still.
        let again = inspect(&format!("mstr1:{}", body(REAL_TICKET, &[10u8; SECRET_LEN]))).unwrap();
        assert_eq!(again.endpoint_id, cred.endpoint_id);
        // A guest ticket names its kind.
        let json = format!(r#"{{"t":"{REAL_TICKET}","g":"guest-token"}}"#);
        let guest = format!("mstrfedg1:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json));
        assert_eq!(inspect(&guest).unwrap().kind, PairingKind::FederationGuest);
    }

    #[test]
    fn a_bad_code_is_a_typed_error_with_the_old_words() {
        let err = inspect("mstr9:whatever").unwrap_err();
        assert!(matches!(err, DialError::BadCode(_)));
        assert!(err.to_string().contains("Update"), "{err}");
        assert!(!err.is_rejected());
        assert!(matches!(inspect("garbage").unwrap_err(), DialError::BadCode(_)));
        // The refusal keeps the word the bindings and the harness match on.
        let refused = DialError::Rejected { kind: PairingKind::Tunnel };
        assert!(refused.is_rejected());
        assert!(refused.to_string().contains("rejected"));
        assert!(DialError::Rejected { kind: PairingKind::FederationGuest }.to_string().contains("rejected"));
    }

    /// The whole client path against a live endpoint speaking the server's
    /// protocol — parse, bind, dial, handshake, bridge, one HTTP round trip
    /// with the loopback token — with the stages reported in order; then a
    /// wrong secret, refused as a typed rejection.
    #[test]
    fn dials_through_the_stages_and_a_wrong_secret_is_rejected() {
        const SECRET: [u8; SECRET_LEN] = [42u8; SECRET_LEN];
        let rt = runtime();
        let ticket = fake_mstream_endpoint(
            &rt,
            SECRET,
            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nhi",
        );
        let code = format!("mstr1:{}", body(&ticket, &SECRET));

        let mut stages = Vec::new();
        let tunnel = rt
            .block_on(connect_tunnel_staged(&code, 0, &mut |stage| stages.push(stage)))
            .expect("open tunnel");
        assert_eq!(stages[0], Stage::Bound);
        assert!(matches!(stages[1], Stage::Relay { .. }), "{stages:?}");
        assert_eq!(&stages[2..], &[Stage::Connected, Stage::Handshaken, Stage::Serving { local_port: tunnel.local_port }]);
        assert_eq!(tunnel.local_url(), format!("http://127.0.0.1:{}", tunnel.local_port));
        assert_eq!(tunnel.kind(), PairingKind::Tunnel);

        use std::io::{Read, Write};
        let mut sock = std::net::TcpStream::connect(("127.0.0.1", tunnel.local_port)).expect("connect bridge");
        let request = format!(
            "GET /api/v1/ping?__lt={} HTTP/1.1\r\nhost: tunnel\r\nconnection: close\r\n\r\n",
            tunnel.local_token()
        );
        sock.write_all(request.as_bytes()).expect("send request");
        sock.shutdown(std::net::Shutdown::Write).expect("half-close");
        let mut reply = String::new();
        let _ = sock.read_to_string(&mut reply);
        assert!(reply.starts_with("HTTP/1.1 200 OK") && reply.ends_with("hi"), "got: {reply}");
        tunnel.begin_shutdown(&rt);

        let wrong = format!("mstr1:{}", body(&ticket, &[1u8; SECRET_LEN]));
        let err = match rt.block_on(connect_tunnel(&wrong, 0)) {
            Ok(_) => panic!("a wrong secret must be refused"),
            Err(e) => e,
        };
        assert_eq!(err, DialError::Rejected { kind: PairingKind::Tunnel });
        assert!(err.to_string().contains("rejected"));
    }

    fn body(t: &str, secret: &[u8]) -> String {
        let s = base64::engine::general_purpose::STANDARD.encode(secret);
        let json = format!(r#"{{"t":"{t}","s":"{s}"}}"#);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes())
    }

    #[test]
    fn parses_versioned_envelope() {
        let secret = [7u8; SECRET_LEN];
        let p = parse_pairing_code(&format!("mstr1:{}", body("endpointabc", &secret))).unwrap();
        assert_eq!(p.ticket, "endpointabc");
        assert_eq!(p.payload, secret.to_vec());
        assert_eq!(p.alpn, TUNNEL_ALPN);
        assert_eq!(p.kind, PairingKind::Tunnel);
    }

    #[test]
    fn parses_legacy_bare_as_v1() {
        let p = parse_pairing_code(&body("endpointlegacy", &[1u8; SECRET_LEN])).unwrap();
        assert_eq!(p.ticket, "endpointlegacy");
    }

    #[test]
    fn trims_surrounding_whitespace() {
        let code = format!("  mstr1:{}\n", body("endpointws", &[2u8; SECRET_LEN]));
        assert_eq!(parse_pairing_code(&code).unwrap().ticket, "endpointws");
    }

    #[test]
    fn rejects_newer_version_with_update_hint() {
        let err = parse_pairing_code(&format!("mstr2:{}", body("x", &[0u8; SECRET_LEN])))
            .unwrap_err()
            .to_string();
        assert!(err.contains("version 2"), "got: {err}");
        assert!(err.to_lowercase().contains("update"), "got: {err}");
    }

    #[test]
    fn backoff_doubles_and_caps_unless_woken() {
        let mut b = Duration::from_secs(1);
        let mut seen = vec![];
        for _ in 0..6 {
            b = next_backoff(b, false);
            seen.push(b.as_secs());
        }
        assert_eq!(seen, vec![2, 4, 8, 10, 10, 10]);
        assert_eq!(next_backoff(Duration::from_secs(10), true).as_secs(), 1);
    }

    #[tokio::test]
    async fn a_spent_kick_does_not_wake_the_backoff() {
        // Mirrors production: no receiver is kept, subscribers are created on demand.
        let (tx, _) = watch::channel(0u64);
        tx.send_modify(|g| *g += 1); // a kick from a previous connected period
        let seen = *tx.borrow(); // the attempt starts after it
        let woke = tokio::time::timeout(Duration::from_millis(50), kick_after(&tx, seen)).await;
        assert!(
            woke.is_err(),
            "a kick older than the attempt must not cut its backoff"
        );
    }

    #[tokio::test]
    async fn a_kick_during_or_after_the_attempt_wakes_the_backoff() {
        let (tx, _) = watch::channel(0u64);
        // During the attempt: the generation moved before the wait began.
        let seen = *tx.borrow();
        tx.send_modify(|g| *g += 1);
        let woke = tokio::time::timeout(Duration::from_millis(50), kick_after(&tx, seen)).await;
        assert!(
            woke.is_ok(),
            "a kick during the attempt cuts the backoff at once"
        );
        // While waiting: the kick lands mid-sleep.
        let seen = *tx.borrow();
        let (_, woke) = tokio::join!(
            async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                tx.send_modify(|g| *g += 1);
            },
            tokio::time::timeout(Duration::from_millis(500), kick_after(&tx, seen)),
        );
        assert!(woke.is_ok(), "a kick that lands mid-backoff wakes it");
    }

    #[test]
    fn event_ring_caps_and_counts_drops() {
        let mut r = EventRing::new();
        assert!(r.drain().is_none());
        for i in 0..(EVENT_RING_CAP + 3) {
            r.push(format!("e{i}"));
        }
        let out = r.drain().unwrap();
        assert!(out.starts_with("(3 older events dropped)\n"), "got: {out}");
        assert!(out.contains("e3\n"));
        assert!(!out.contains("e2\n"));
        assert!(out.trim_end().ends_with(&format!("e{}", EVENT_RING_CAP + 2)));
        assert!(r.drain().is_none(), "drain empties the ring");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_pairing_code("not-a-real-ticket!!").is_err());
    }

    #[test]
    fn rejects_missing_secret() {
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"t":"only"}"#);
        assert!(parse_pairing_code(&format!("mstr1:{b}")).is_err());
    }

    #[test]
    fn rejects_wrong_secret_length() {
        assert!(parse_pairing_code(&format!("mstr1:{}", body("endpointx", &[9u8; 10]))).is_err());
    }

    // ── federation guest tickets (mstrfedg<V>:) ──

    fn guest_body(t: &str, g: &str) -> String {
        let json = format!(r#"{{"t":"{t}","g":"{g}"}}"#);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes())
    }

    #[test]
    fn parses_guest_ticket_onto_the_federation_alpn() {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJmZWRlcmF0aW9uR3Vlc3QiOnRydWV9.sig";
        let p = parse_pairing_code(&format!("mstrfedg1:{}", guest_body("endpointpeer", token))).unwrap();
        assert_eq!(p.ticket, "endpointpeer");
        assert_eq!(p.payload, token.as_bytes());
        assert_eq!(p.alpn, FEDERATION_ALPN);
        assert_eq!(p.kind, PairingKind::FederationGuest);
    }

    #[test]
    fn guest_ticket_refuses_empty_oversized_and_missing_tokens() {
        assert!(parse_pairing_code(&format!("mstrfedg1:{}", guest_body("e", ""))).is_err());
        let huge = "x".repeat(GUEST_TOKEN_MAX + 1);
        assert!(parse_pairing_code(&format!("mstrfedg1:{}", guest_body("e", &huge))).is_err());
        let fits = "x".repeat(GUEST_TOKEN_MAX);
        assert!(parse_pairing_code(&format!("mstrfedg1:{}", guest_body("e", &fits))).is_ok());
        let no_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"t":"only"}"#);
        assert!(parse_pairing_code(&format!("mstrfedg1:{no_token}")).is_err());
    }

    #[test]
    fn guest_ticket_rejects_newer_version_with_update_hint() {
        let err = parse_pairing_code(&format!("mstrfedg2:{}", guest_body("e", "tok")))
            .unwrap_err()
            .to_string();
        assert!(err.contains("version 2"), "got: {err}");
        assert!(err.to_lowercase().contains("update"), "got: {err}");
    }

    #[test]
    fn a_federation_ticket_is_refused_by_name() {
        // mstrfed1: carries a standing server key — the app must never hold one.
        let fed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"t":"e","k":"fedk_x"}"#);
        let err = parse_pairing_code(&format!("mstrfed1:{fed}")).unwrap_err().to_string();
        assert!(err.contains("federation ticket"), "got: {err}");
    }

    #[test]
    fn the_envelopes_stay_disjoint() {
        // A guest ticket never parses as a tunnel code and vice versa.
        let secret = [3u8; SECRET_LEN];
        let tunnel = format!("mstr1:{}", body("e", &secret));
        assert_eq!(parse_pairing_code(&tunnel).unwrap().kind, PairingKind::Tunnel);
        let guest = format!("mstrfedg1:{}", guest_body("e", "tok"));
        assert_eq!(parse_pairing_code(&guest).unwrap().kind, PairingKind::FederationGuest);
    }
}
