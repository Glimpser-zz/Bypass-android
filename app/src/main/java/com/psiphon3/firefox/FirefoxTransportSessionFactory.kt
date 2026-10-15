package com.psiphon3.firefox

import java.io.IOException

/**
 * Creates a real HTTP/2 upstream session from a Guardian proxy pass.
 *
 * Callers must obtain host/port from Mozilla's current VPN server list. This class
 * intentionally does not guess endpoints or report a VPN as connected until connect()
 * has completed. It is not yet attached to Bypass's packet/TUN forwarding loop.
 */
class FirefoxTransportSessionFactory(
    private val edgeAddress: String? = null,
    private val upstreamProxy: UpstreamProxyConfig? = null,
) {
    suspend fun connect(candidate: FirefoxServerCandidate, proxyPass: GuardianControlPlane.ProxyPass): UpstreamSession =
        connect(candidate.host, candidate.port, proxyPass)

    suspend fun connect(host: String, port: Int, proxyPass: GuardianControlPlane.ProxyPass): UpstreamSession {
        require(host.isNotBlank()) { "Firefox upstream host is required" }
        require(port in 1..65535) { "Firefox upstream port is invalid" }
        require(proxyPass.token.isNotBlank()) { "Guardian proxy pass is empty" }
        proxyPass.expiresAtEpochSeconds?.let {
            if (it <= System.currentTimeMillis() / 1000) {
                throw IOException("Guardian proxy pass has expired")
            }
        }

        val session = FirefoxH2UpstreamSession(
            upstreamHost = host,
            upstreamPort = port,
            bearerToken = proxyPass.token,
            upstreamProxy = upstreamProxy,
            edgeAddress = edgeAddress,
        )
        try {
            session.connect()
            if (!session.isConnected) throw IOException("Firefox HTTP/2 upstream did not become connected")
            return session
        } catch (failure: Exception) {
            runCatching { session.close() }
            throw failure
        }
    }
}
