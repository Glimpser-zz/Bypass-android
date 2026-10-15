/*
 * Copyright (C) 2026 Glimpser
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * HTTP client for Mozilla Guardian control-plane requests.
 * The socket protector must be set by the active VpnService before network calls,
 * otherwise control-plane requests can recurse into the VPN interface.
 */
package com.psiphon3.firefox

import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory

class FirefoxCookieJar : CookieJar {
    private val cookies = ConcurrentHashMap<String, MutableList<Cookie>>()

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        for (cookie in cookies) {
            val domainCookies = this.cookies.getOrPut(cookie.domain) { mutableListOf() }
            synchronized(domainCookies) {
                domainCookies.removeAll { it.name == cookie.name && it.path == cookie.path }
                if (cookie.expiresAt > System.currentTimeMillis()) domainCookies.add(cookie)
            }
        }
    }

    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        val now = System.currentTimeMillis()
        val result = mutableListOf<Cookie>()
        for ((domain, values) in cookies) {
            if (url.host == domain || url.host.endsWith(".$domain")) {
                synchronized(values) {
                    values.removeAll { it.expiresAt <= now }
                    result.addAll(values.filter { it.matches(url) })
                }
            }
        }
        return result
    }
}

object FirefoxControlPlaneHttp {
    @Volatile
    var socketProtector: ((Socket) -> Boolean)? = null

    val cookieJar = FirefoxCookieJar()

    private class ProtectedSocketFactory : SocketFactory() {
        private fun protect(socket: Socket, local: InetSocketAddress? = null): Socket {
            if (!socket.isBound) socket.bind(local ?: InetSocketAddress(0))
            val protector = socketProtector
            if (protector != null && !runCatching { protector(socket) }.getOrDefault(false)) {
                socket.close()
                throw java.io.IOException("VpnService.protect() failed for Firefox control-plane socket")
            }
            return socket
        }

        override fun createSocket(): Socket = protect(Socket())
        override fun createSocket(host: String, port: Int): Socket =
            protect(Socket()).apply { connect(InetSocketAddress(host, port)) }
        override fun createSocket(host: String, port: Int, localAddr: InetAddress, localPort: Int): Socket =
            protect(Socket(), InetSocketAddress(localAddr, localPort)).apply { connect(InetSocketAddress(host, port)) }
        override fun createSocket(host: InetAddress, port: Int): Socket =
            protect(Socket()).apply { connect(InetSocketAddress(host, port)) }
        override fun createSocket(host: InetAddress, port: Int, localAddr: InetAddress, localPort: Int): Socket =
            protect(Socket(), InetSocketAddress(localAddr, localPort)).apply { connect(InetSocketAddress(host, port)) }
    }

    val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .cookieJar(cookieJar)
            .socketFactory(ProtectedSocketFactory())
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .callTimeout(30, TimeUnit.SECONDS)
            .build()
    }
}
