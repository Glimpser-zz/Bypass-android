package com.psiphon3.firefox

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.Closeable

/** Owns the Firefox upstream and loopback SOCKS listener for one service lifetime. */
class FirefoxTunnelRuntime(context: Context) : Closeable {
    private val sessionStore = FirefoxSessionStore(context.applicationContext)
    private val transportSettings = FirefoxTransportSettingsStore(context.applicationContext)
    private val coordinator = FirefoxConnectionCoordinator(
        preflight = FirefoxConnectionPreflight(sessionStore, FirefoxTokenRefresher(sessionStore)),
        factory = FirefoxTransportSessionFactory(edgeAddress = transportSettings.loadEdgeAddress()),
    )

    @Volatile
    private var active: FirefoxConnectionCoordinator.Result.SocksReady? = null

    fun connectBlocking(): FirefoxConnectionCoordinator.Result {
        return try {
            when (val result = runBlocking(Dispatchers.IO) { coordinator.connectWithSocks5() }) {
                is FirefoxConnectionCoordinator.Result.SocksReady -> {
                    active = result
                    result
                }
                else -> result
            }
        } catch (e: Exception) {
            FirefoxConnectionCoordinator.Result.Failed(
                e.message ?: "Firefox VPN connection failed",
                retryable = true,
            )
        }
    }

    override fun close() {
        val ready = active
        active = null
        if (ready != null) {
            runCatching { ready.socksServer.close() }
            runCatching { ready.session.close() }
        }
    }
}
