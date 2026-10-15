package com.psiphon3.firefox

import javax.net.ssl.TrustManagerFactory

/**
 * Uses Android's default TLS trust configuration. A dedicated merged trust store
 * can be added after the transport is verified against supported Android versions.
 */
internal object FirefoxUpstreamTrust {
    fun trustManagerFactory(): TrustManagerFactory? = null
}
