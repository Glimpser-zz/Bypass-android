package com.psiphon3.firefox

import kotlinx.coroutines.runBlocking
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * SOCKS5 UDP ASSOCIATE relay limited to DNS (port 53).
 * The Guardian HTTP/2 upstream carries TCP streams, so DNS datagrams are
 * converted to DNS-over-TCP. Other UDP protocols are deliberately dropped.
 */
internal class FirefoxSocks5UdpDnsRelay(
    private val upstream: UpstreamSession,
    private val clientAddress: InetAddress,
) : Closeable {
    private val closed = AtomicBoolean(false)
    private val clientPort = AtomicInteger(-1)
    private val socket = DatagramSocket(null)
    private val workers = Executors.newFixedThreadPool(4)
    private val receiver = Executors.newSingleThreadExecutor()

    val port: Int get() = socket.localPort
    val address: InetAddress get() = InetAddress.getByName("127.0.0.1")

    init {
        socket.reuseAddress = false
        socket.bind(InetSocketAddress(address, 0))
        socket.soTimeout = 0
    }

    fun start() {
        receiver.execute {
            val buffer = ByteArray(MAX_PACKET_BYTES)
            while (!closed.get()) {
                try {
                    val packet = DatagramPacket(buffer, buffer.size)
                    socket.receive(packet)
                    if (packet.address != clientAddress) continue

                    val pinnedPort = clientPort.get()
                    if (pinnedPort == -1) {
                        clientPort.compareAndSet(-1, packet.port)
                    }
                    if (clientPort.get() != packet.port) continue

                    val data = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                    workers.execute { handle(data, InetSocketAddress(packet.address, packet.port)) }
                } catch (e: SocketException) {
                    if (!closed.get()) FirefoxLog.w(TAG, "UDP DNS socket failed", e)
                    break
                } catch (e: IOException) {
                    if (!closed.get()) FirefoxLog.d(TAG, "UDP DNS receive failed: ${e.message}")
                }
            }
        }
    }

    private fun handle(packet: ByteArray, replyTo: InetSocketAddress) {
        val parsed = parse(packet) ?: return
        if (parsed.port != DNS_PORT || parsed.payloadOffset >= packet.size) return
        val query = packet.copyOfRange(parsed.payloadOffset, packet.size)
        if (query.size > MAX_DNS_BYTES) return

        val answer = try {
            val stream = runBlocking { upstream.openStream(parsed.host, DNS_PORT) }
            try {
                val out = DataOutputStream(stream.output)
                out.writeShort(query.size)
                out.write(query)
                out.flush()

                val input = DataInputStream(stream.input)
                val size = input.readUnsignedShort()
                if (size !in 1..MAX_DNS_BYTES) throw IOException("Invalid DNS response size: $size")
                ByteArray(size).also { bytes -> input.readFully(bytes) }
            } finally {
                stream.close()
            }
        } catch (e: Exception) {
            FirefoxLog.d(TAG, "UDP DNS query failed: ${e.message}")
            null
        } ?: return

        val response = packet.copyOfRange(0, parsed.payloadOffset) + answer
        runCatching { socket.send(DatagramPacket(response, response.size, replyTo)) }
    }

    private data class Parsed(val host: String, val port: Int, val payloadOffset: Int)

    private fun parse(data: ByteArray): Parsed? {
        if (data.size < 10 || data[0].toInt() != 0 || data[1].toInt() != 0 || data[2].toInt() != 0) return null
        var i = 4
        val host = when (data[3].toInt() and 0xff) {
            1 -> {
                if (data.size < i + 6) return null
                val b = data.copyOfRange(i, i + 4); i += 4
                b.joinToString(".") { (it.toInt() and 255).toString() }
            }
            3 -> {
                if (data.size <= i) return null
                val n = data[i++].toInt() and 255
                if (n == 0 || data.size < i + n + 2) return null
                String(data, i, n, Charsets.US_ASCII).also { i += n }
            }
            4 -> {
                if (data.size < i + 18) return null
                val b = data.copyOfRange(i, i + 16); i += 16
                runCatching { InetAddress.getByAddress(b).hostAddress }.getOrNull() ?: return null
            }
            else -> return null
        }
        if (data.size < i + 2) return null
        val port = ((data[i].toInt() and 255) shl 8) or (data[i + 1].toInt() and 255)
        i += 2
        return Parsed(host, port, i)
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        socket.close()
        receiver.shutdownNow()
        workers.shutdownNow()
    }

    private companion object {
        const val TAG = "FirefoxUdpDnsRelay"
        const val DNS_PORT = 53
        const val MAX_DNS_BYTES = 4096
        const val MAX_PACKET_BYTES = 4608
    }
}
