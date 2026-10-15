# Firefox VPN / CDN Fronting integration

## Goal

Add a selectable Firefox VPN (Mozilla Guardian) transport to Bypass-android while preserving the existing Psiphon transport and its current CDN-fronting behavior.

## Important architecture constraint

Bypass-android is a Java/Gradle Psiphon client. G-FoxyVPN is a separate Kotlin application with its own Android VPN service, Compose UI, authentication repository, Guardian API client, HTTP/2 upstream implementation, and native hev-socks5 tunnel. Copying its `VpnService` into Bypass would create competing VPN ownership and is not a safe integration.

The intended integration is to reuse the Firefox control-plane and HTTP/2 upstream components behind Bypass's existing single VPN service, not start a second VPN service. This requires a deliberate adapter between Bypass's traffic-routing path and G-FoxyVPN's `UpstreamSession` / local SOCKS5 relay.

## Source components reviewed

From G-FoxyVPN:
- `data/FxaAuthRepository.kt`, `data/TokenStore.kt`: Firefox account authentication and token persistence.
- `data/GuardianClient.kt`, `data/FastlyChallengeSolver.kt`: Guardian entitlement/proxy-pass flow.
- `data/ServerListClient.kt`, `vpn/upstream/EdgeAddressResolver.kt`: server/edge discovery.
- `vpn/upstream/H2UpstreamSession.kt`: HTTP/2 upstream tunnel and upstream proxy support.
- `vpn/socks/LocalSocks5Server.kt`: SOCKS5 relay backed by the HTTP/2 session.

From Bypass-android:
- `com.psiphon3.VpnManager`, the Psiphon tunnel service/interactor and existing upstream-proxy settings are the integration points to inspect.
- `app/build.gradle` currently applies only the Android application plugin; it does not enable Kotlin. G-FoxyVPN requires Kotlin, coroutines, OkHttp, Netty, Conscrypt, and related dependencies.

## Additional finding from the code inspection

Bypass's `TunnelManager.buildTunnelCoreConfig()` supports Psiphon's `UpstreamProxyUrl` option. That option configures a proxy *for Psiphon's own server connections*; it does not replace Psiphon's transport with the Firefox VPN protocol. Pointing it at a local Firefox-backed proxy would therefore layer Psiphon over Firefox rather than make Bypass use Firefox as its selected VPN transport. It is not a valid substitute for the requested mode.

G-FoxyVPN's HTTP/2 upstream is also not a generic CDN-fronting socket: its edge resolution, TLS identity, HTTP/2 CONNECT headers, proxy-pass token and challenge flow must remain consistent. A transport adapter must be integrated with the existing traffic-routing implementation, or the existing TUN-to-SOCKS path must be deliberately replaced for Firefox mode. The current codebase does not expose a one-line switch that safely accomplishes this.

## Required implementation sequence

1. Add Kotlin support and isolate the minimum reusable Firefox control-plane/upstream code in a package that can coexist with the existing Java app.
2. Implement a transport adapter and lifecycle owned by Bypass's existing VPN service. Do not declare or start a second `VpnService`.
3. Define how CDN fronting changes the HTTP/2 connection's edge address, TLS SNI, certificate verification, HTTP/2 authority, and request headers. These values must be based on the existing Bypass implementation and supported by the selected edge; simply changing a hostname is not sufficient.
4. Add a UI choice between the current Psiphon transport and Firefox VPN transport, with existing mode remaining the default.
5. Add tests for authentication/token expiry, edge selection, TLS/HTTP/2 handshake, reconnects, and traffic routing.
6. Build and test on-device before calling the feature complete. In particular, verify the Firefox mode routes device traffic directly through its own TUN/SOCKS-to-HTTP/2 path and does not accidentally start Psiphon in front of it.

## Current status

The integration branch now has these preparatory code changes:
- Kotlin Gradle plugin enabled for the app module.
- Minimum Android version raised to API 26 (Android 8.0), as agreed for the planned transport dependencies.
- OkHttp, coroutines, Netty HTTP/2, Netty proxy handlers, and Conscrypt dependencies added.
- A new `com.psiphon3.firefox.GuardianControlPlane` client can request Guardian account status and a proxy pass when the caller supplies a valid Firefox access token. HTTP 406 challenge requirements are surfaced explicitly; this client does not bypass or fake the challenge.
- Added `FirefoxControlPlaneHttp`, a shared OkHttp client with cookie persistence and socket-protection lifecycle hooks. `TunnelVpnService` now attaches itself on creation and detaches on destruction/revocation so future control-plane sockets can be protected from VPN routing recursion. This lifecycle wiring does not yet start Firefox network requests or provide a data plane.
- Added `FirefoxSession` and `FirefoxSessionStore`; the latter persists access/refresh tokens in AndroidX encrypted preferences and checks access-token expiry.
- Added `FirefoxTokenRefresher` for refreshing an already-authorized OAuth session and persisting the rotated tokens. It does not perform password sign-in, two-factor authentication, or Fastly challenge handling, and it has not been validated against a live account.
- Added `FirefoxConnectionPreflight` to coordinate local session expiry checks, token refresh, Guardian account status and proxy-pass retrieval. It reports sign-in-required, challenge-required and retryable failures separately. A successful preflight is not a connected tunnel; it still does not route user traffic.

The feature is still **not end-to-end implemented**. Firefox Account sign-in/token refresh, challenge solving, server/edge selection, the HTTP/2 data plane, integration with Bypass's existing VPN lifecycle, and the mode selector remain outstanding. No successful build or real-network test has been claimed.


## HTTP/2 upstream transport port (not yet end-to-end)

- Ported the Firefox VPN HTTP/2 upstream session implementation into `FirefoxH2UpstreamSession`, including HTTP/2 CONNECT streams, TLS/ALPN, stream lifecycle and bearer proxy-pass updates.
- Added `FirefoxTransportSessionFactory`, which accepts an explicit server host/port and a Guardian proxy pass, then establishes and verifies the upstream session.
- The transport uses the existing Bypass VPN service's socket-protection callback for Netty sockets. Android's platform TLS trust is used for now.
- This is a transport primitive only. Bypass does not yet fetch/select the Mozilla server list, adapt its packet/TUN loop to open these streams, or connect this session to its existing local forwarding pipeline. No user traffic should be assumed to pass through Firefox at this point.
- Build and device verification remain outstanding; copied transport code has not yet been validated against Bypass's exact dependency graph and Android build.


## Connection orchestration

- Added `FirefoxConnectionCoordinator` to run Guardian preflight, fetch Mozilla server candidates, optionally filter by country code, and attempt HTTP/2 connections until one succeeds.
- The coordinator returns the chosen endpoint and live upstream session, or a typed sign-in/challenge/failure result. It deliberately does not claim the device VPN is connected.
- The returned HTTP/2 session still needs to be integrated with the app's TUN packet forwarding and per-flow TCP handling. No user traffic is routed through it yet.


## Endpoint selection hardening

- Server discovery now falls back to a server record's hostname and port when no usable CONNECT endpoint is present in its protocol list.
- The coordinator tries at most four randomized candidates per attempt, rather than potentially serially waiting on every server in a country. A caller may retry after a failure.
- These changes improve bounded failure behavior; they do not replace an Android TUN-to-stream data plane or substitute for build and device testing.


## Existing Bypass VPN routing: integration boundary

A source review confirms that Bypass already owns the Android `VpnService` and uses `VpnManager.routeThroughTunnel(socksProxyPort)` to start its native tun2socks path. `TunnelManager` currently calls this with the Psiphon core's local SOCKS port after the Psiphon tunnel reports connected.

That means the Firefox mode cannot be implemented correctly by only changing `UpstreamProxyUrl`: that setting configures the Psiphon core's upstream connections and would create a layered connection, not replace the Psiphon data plane.

The next implementation stage needs three explicit lifecycle pieces before UI exposure:

1. A loopback SOCKS5 listener whose CONNECT requests open streams on `UpstreamSession` and relay bytes in both directions.
2. A mutually exclusive tunnel-start path in `TunnelManager` that skips starting the Psiphon core for Firefox mode, establishes the existing Android VPN interface, and passes the listener's port to `VpnManager.routeThroughTunnel(...)`.
3. A stop/revoke/network-change lifecycle that closes accepted sockets, the listener, HTTP/2 streams, and the upstream session without leaving traffic routed into a dead port.

The SOCKS listener must bind only to loopback, and the app must not advertise a connected VPN until the Android VPN interface, listener, and upstream session are all ready. This stage has not yet been implemented or tested; the current coordinator only opens the upstream HTTP/2 session.


## Loopback SOCKS5 adapter status

The branch now contains `FirefoxH2Socks5Server`, a loopback-only SOCKS5 CONNECT listener that opens a stream through an already-connected `UpstreamSession` and relays TCP bytes. `FirefoxConnectionCoordinator.connectWithSocks5()` combines upstream setup with listener startup and returns the listener/port for an eventual tunnel owner to manage.

This is an intermediate transport milestone only. The SOCKS5 listener currently supports TCP CONNECT (not arbitrary UDP); DNS behavior depends on the existing tun2socks configuration. It has not been compiled or exercised against a real Guardian endpoint. The current Bypass `TunnelManager` does not yet call `connectWithSocks5()`, establish a Firefox-only tunnel lifecycle, or pass this listener port to `VpnManager.routeThroughTunnel()`. Do not expose this as a working VPN mode until those pieces and shutdown/error handling are integrated and tested.
