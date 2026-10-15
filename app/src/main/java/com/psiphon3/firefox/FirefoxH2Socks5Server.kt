package com.psiphon3.firefox

import kotlinx.coroutines.runBlocking
import java.io.Closeable
import java.io.EOFException
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Loopback SOCKS5 adapter for an already-connected HTTP/2 upstream.
 * This is not itself a VPN; the existing tun2socks path must be pointed at its port.
 */
class FirefoxH2Socks5Server(
    private val upstream: UpstreamSession,
    private val requestedPort: Int = 0,
) : Closeable {
    private val closed = AtomicBoolean(false)
    private val workers = Executors.newCachedThreadPool()
    @Volatile private var server: ServerSocket? = null

    val port: Int get() = server?.localPort ?: error("SOCKS5 listener is not started")

    @Synchronized
    fun start(): Int {
        check(!closed.get()) { "Listener is closed" }
        check(server == null) { "Listener already started" }
        check(upstream.isConnected) { "HTTP/2 upstream is not connected" }
        val socket = ServerSocket()
        socket.reuseAddress = false
        // The UDP DNS relay advertises 127.0.0.1, so keep the TCP listener IPv4 too.
        socket.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), requestedPort), 64)
        server = socket
        workers.execute {
            while (!closed.get()) {
                try {
                    val client = socket.accept()
                    workers.execute { serve(client) }
                } catch (e: SocketException) {
                    if (!closed.get()) FirefoxLog.w(TAG, "accept failed", e)
                    break
                } catch (e: IOException) {
                    if (!closed.get()) FirefoxLog.w(TAG, "accept failed", e)
                }
            }
        }
        return socket.localPort
    }

    private fun serve(client: Socket) {
        client.use { s ->
            try {
                s.soTimeout = 10_000
                val input = s.getInputStream()
                val output = s.getOutputStream()
                if (input.read() != 5) return
                val count = input.read()
                if (count !in 1..255) return
                val methods = ByteArray(count)
                readFully(input, methods)
                if (methods.none { it.toInt() == 0 }) {
                    output.write(byteArrayOf(5, 0xff.toByte())); output.flush(); return
                }
                output.write(byteArrayOf(5, 0)); output.flush()
                val ver = input.read()
                val cmd = input.read()
                val reserved = input.read()
                val atyp = input.read()
                if (ver != 5 || reserved != 0) return
                if (cmd != 1 && cmd != 3) { reply(output, 7); return }
                val host = when (atyp) {
                    1 -> { val b = ByteArray(4); readFully(input, b); InetAddress.getByAddress(b).hostAddress }
                    3 -> { val n = input.read(); if (n !in 1..255) return; val b = ByteArray(n); readFully(input, b); String(b, Charsets.US_ASCII) }
                    4 -> { val b = ByteArray(16); readFully(input, b); InetAddress.getByAddress(b).hostAddress }
                    else -> { reply(output, 8); return }
                }
                val p = ByteArray(2); readFully(input, p)
                val targetPort = ((p[0].toInt() and 255) shl 8) or (p[1].toInt() and 255)
                if (cmd == 3) {
                    if (targetPort != 0 && targetPort != 53) { reply(output, 2); return }
                    val relay = try {
                        FirefoxSocks5UdpDnsRelay(upstream, s.inetAddress)
                    } catch (e: Exception) {
                        FirefoxLog.d(TAG, "UDP DNS association failed: ${e.message}")
                        reply(output, 1)
                        return
                    }
                    try {
                        relay.start()
                        output.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1,
                            (relay.port ushr 8).toByte(), relay.port.toByte()))
                        output.flush()
                        val drain = ByteArray(64)
                        while (input.read(drain) >= 0) { /* association lives until TCP control closes */ }
                    } finally {
                        relay.close()
                    }
                    return
                }
                if (targetPort == 0) { reply(output, 1); return }
                s.soTimeout = 0
                val stream = try {
                    runBlocking { upstream.openStream(host, targetPort) }
                } catch (e: Exception) {
                    FirefoxLog.d(TAG, "CONNECT failed for $host:$targetPort: ${e.message}")
                    reply(output, 5); return
                }
                reply(output, 0)
                val upstreamWriter = workers.submit {
                    try { input.copyTo(stream.output, 32 * 1024) }
                    catch (_: Exception) { }
                    finally { runCatching { stream.output.close() } }
                }
                try {
                    stream.input.copyTo(output, 32 * 1024)
                    runCatching { s.shutdownOutput() }
                    upstreamWriter.get()
                } finally {
                    upstreamWriter.cancel(true)
                    stream.close()
                }
            } catch (e: EOFException) {
                FirefoxLog.d(TAG, "client closed during SOCKS handshake")
            } catch (e: Exception) {
                if (!closed.get()) FirefoxLog.d(TAG, "client connection ended: ${e.message}")
            }
        }
    }

    private fun reply(output: java.io.OutputStream, code: Int) {
        output.write(byteArrayOf(5, code.toByte(), 0, 1, 0, 0, 0, 0, 0, 0))
        output.flush()
    }

    private fun readFully(input: java.io.InputStream, bytes: ByteArray) {
        var offset = 0
        while (offset < bytes.size) {
            val n = input.read(bytes, offset, bytes.size - offset)
            if (n < 0) throw EOFException("Unexpected EOF")
            offset += n
        }
    }

    @Synchronized
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { server?.close() }
        server = null
        workers.shutdownNow()
    }

    private companion object { const val TAG = "FirefoxH2Socks5" }
}
