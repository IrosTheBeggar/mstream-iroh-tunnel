/* mstream-iroh-tunnel — the C ABI of the mStream tunnel client. See README.md. */

#ifndef MSTREAM_IROH_H
#define MSTREAM_IROH_H

/* Generated with cbindgen:0.29.4 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Tunnel status, shared with the C ABI / Dart (keep values in sync with
 * `lib/native/iroh_tunnel.dart`).
 */
#define STATUS_CONNECTING 0

#define STATUS_CONNECTED 1

#define STATUS_RECONNECTING 2

#define STATUS_REJECTED 3

#define STATUS_DOWN 4

/**
 * Selected-path kind, shared with the C ABI / Dart (`IrohPathKind`).
 */
#define PATH_UNKNOWN 0

#define PATH_DIRECT 1

#define PATH_RELAY 2

/**
 * Bumped when the C ABI changes shape. v1: one global tunnel. v2: tunnels
 * keyed by an app-chosen id, plus `set_credential`. The Dart side probes
 * `mstream_iroh_abi_version` and refuses a binary older than it expects.
 */
#define ABI_VERSION 2

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * The C ABI version this binary implements (see [`crate::ffi::ABI_VERSION`]).
 * Absent from v1 binaries — the Dart side treats a missing symbol as v1.
 */
 int32_t mstream_iroh_abi_version(void);

/**
 * The crate version this binary was built from, as a heap C string the caller
 * OWNS and must free with [`mstream_iroh_string_free`]. Additive to ABI v2 —
 * a binding that finds the symbol missing is holding an older binary.
 */
 char *mstream_iroh_version(void);

/**
 * Start the tunnel for `key` from a NUL-terminated UTF-8 code (a Quick Connect
 * pairing code or a federation guest ticket). Returns the loopback port (> 0)
 * on success, or -1 on error — then call [`mstream_iroh_last_error`].
 * Idempotent per key (returns the existing port if that key is running).
 *
 * # Safety
 * `key` and `code` must be valid NUL-terminated C strings for the duration of the call.
 */
 int32_t mstream_iroh_start(const char *key, const char *code, uint16_t local_port);

/**
 * Stop the tunnel for `key` (graceful). Safe to call when it isn't running.
 *
 * # Safety
 * `key` must be a valid NUL-terminated C string for the duration of the call.
 */
 void mstream_iroh_stop(const char *key);

/**
 * Whether the tunnel for `key` is currently CONNECTED.
 *
 * # Safety
 * `key` must be a valid NUL-terminated C string for the duration of the call.
 */
 bool mstream_iroh_is_active(const char *key);

/**
 * Current status of the tunnel for `key`: one of the STATUS_* codes
 * (0=connecting, 1=connected, 2=reconnecting, 3=rejected/re-pair, 4=down).
 * Mirrors lib.rs STATUS_* and the Dart `IrohTunnelStatus` enum. 4 when the
 * key has no tunnel.
 *
 * # Safety
 * `key` must be a valid NUL-terminated C string for the duration of the call.
 */
 int32_t mstream_iroh_status(const char *key);

/**
 * Tell every running tunnel the device network changed (call on connectivity
 * transitions — iroh can't self-detect them on Android).
 */
 void mstream_iroh_network_changed(void);

/**
 * Current path kind of the tunnel for `key`: 0=unknown, 1=direct
 * (hole-punched), 2=relayed. Mirrors the PATH_* constants in lib.rs and the
 * Dart `IrohPathKind` enum.
 *
 * # Safety
 * `key` must be a valid NUL-terminated C string for the duration of the call.
 */
 int32_t mstream_iroh_path_kind(const char *key);

/**
 * Reconnect the tunnel for `key` in place — same loopback port and token —
 * after the app has confirmed (two failed liveness probes) that a tunnel
 * reporting connected is dead. Non-blocking; no-op when it isn't running.
 *
 * # Safety
 * `key` must be a valid NUL-terminated C string for the duration of the call.
 */
 void mstream_iroh_force_reconnect(const char *key);

/**
 * Swap the credential the tunnel for `key` dials with (a refreshed guest
 * ticket, or a new pairing code for the same server), in place — same port,
 * same token. Returns 0 on success, -1 on error (then call
 * [`mstream_iroh_last_error`]): no such tunnel, an unparseable code, or a
 * code for a different server or kind. Non-blocking.
 *
 * # Safety
 * `key` and `code` must be valid NUL-terminated C strings for the duration of the call.
 */
 int32_t mstream_iroh_set_credential(const char *key, const char *code);

/**
 * Native events for the tunnel for `key` since the last call as a heap
 * NUL-terminated C string (one event per line) the caller must free with
 * [`mstream_iroh_string_free`], or null when there is nothing new. The app
 * appends them to its diagnostics log.
 *
 * # Safety
 * `key` must be a valid NUL-terminated C string for the duration of the call.
 */
 char *mstream_iroh_drain_events(const char *key);

/**
 * Whether the tunnel for `key` has a home relay connected: 1 yes, 0 no, -1
 * unknown (no such tunnel).
 *
 * # Safety
 * `key` must be a valid NUL-terminated C string for the duration of the call.
 */
 int32_t mstream_iroh_relay_online(const char *key);

/**
 * The loopback auth token of the tunnel for `key` as a heap NUL-terminated C
 * string the caller must free with [`mstream_iroh_string_free`], or null if
 * it isn't running. The app appends it to loopback URLs as `__lt=<token>`.
 *
 * # Safety
 * `key` must be a valid NUL-terminated C string for the duration of the call.
 */
 char *mstream_iroh_local_token(const char *key);

/**
 * The last error message as a heap-allocated NUL-terminated C string, or null if
 * none. The caller OWNS the returned pointer and must free it with
 * [`mstream_iroh_string_free`].
 */
 char *mstream_iroh_last_error(void);

/**
 * Free a string returned by any `mstream_iroh_*` function that hands out a
 * heap C string.
 *
 * # Safety
 * `p` must be a pointer previously returned by this library (or null).
 */
 void mstream_iroh_string_free(char *p);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* MSTREAM_IROH_H */
