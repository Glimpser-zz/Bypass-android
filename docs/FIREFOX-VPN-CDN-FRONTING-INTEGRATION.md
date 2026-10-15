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

This document records the initial architecture review. The feature is **not implemented yet**. No runtime behavior has been changed by this document, and a successful build or real-network test has not been claimed. The next code change should be the transport adapter plus the minimal reusable Firefox components, followed by the UI and manifest changes.
