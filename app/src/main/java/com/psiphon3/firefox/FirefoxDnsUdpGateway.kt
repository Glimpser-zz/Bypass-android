package com.psiphon3.firefox

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.Closeable
import java.io.EOFException
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.net.SocketException
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Minimal BadVPN UDPGW-compatible local endpoint for DNS only.
 * DNS is carried as DNS-over-TCP through the HTTP/2 upstream. Other UDP protocols
 * are deliberately not forwarded: this experimental transport is TCP + DNS only.
 */
class FirefoxDnsUdpGateway(
    private val upstream: UpstreamSession,
    private val listenPort: Int = DEFAULT_PORT,
) : Closeable {
    private val closed = AtomicBoolean(false)
    private val workers = Executors.newCachedThreadPool()
    @Volatile private var socket: DatagramSocket? = null
    @Volatile private var receiver: Thread? = null

    fun start() {
        check(!closed.get()) { "DNS gateway is closed" }
        check(socket == null) { "DNS gateway already started" }
        val datagram = DatagramSocket(null)
        datagram.reuseAddress = false
        datagram.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), listenPort))
        socket = datagram
        receiver = Thread({ receiveLoop(datagram) }, "FirefoxDnsUdpGateway").apply {
            isDaemon = true
            start()
        }
    }

    private fun receiveLoop(datagram: DatagramSocket) {
        val buffer = ByteArray(MAX_PACKET_SIZE)
        while (!closed.get()) {
            try {
                val packet = DatagramPacket(buffer, buffer.size)
                datagram.receive(packet)
                val bytes = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                val sender = packet.socketAddress
                workers.execute { handlePacket(bytes, sender) }
            } catch (e: SocketException) {
                if (!closed.get()) FirefoxLog.w(TAG, "DNS gateway socket failed", e)
                break
            } catch (e: IOException) {
                if (!closed.get()) FirefoxLog.w(TAG, "DNS gateway receive failed", e)
            } catch (e: RuntimeException) {
                if (!closed.get()) FirefoxLog.w(TAG, "DNS gateway worker could not be scheduled", e)
            }
        }
    }

    private fun handlePacket(packet: ByteArray, sender: SocketAddress) {
        try {
            // PacketProto: 16-bit little-endian payload length.
            if (packet.size < PACKETPROTO_HEADER + UDPGW_HEADER + IPV4_ADDRESS) return
            val payloadLength = u8(packet[0]) or (u8(packet[1]) shl 8)
            if (payloadLength != packet.size - PACKETPROTO_HEADER) return

            val flags = u8(packet[PACKETPROTO_HEADER])
            val connectionId = u8(packet[PACKETPROTO_HEADER + 1]) or
                (u8(packet[PACKETPROTO_HEADER + 2]) shl 8)
            val isIpv6 = flags and FLAG_IPV6 != 0
            val addressLength = if (isIpv6) IPV6_ADDRESS else IPV4_ADDRESS
            val addressOffset = PACKETPROTO_HEADER + UDPGW_HEADER
            val payloadOffset = addressOffset + addressLength
            if (packet.size <= payloadOffset) return

            val portOffset = addressOffset + if (isIpv6) 16 else 4
            val targetPort = (u8(packet[portOffset]) shl 8) or u8(packet[portOffset + 1])
            if (flags and FLAG_DNS == 0 && targetPort != DNS_PORT) return

            val query = packet.copyOfRange(payloadOffset, packet.size)
            if (query.size < 12 || query.size > MAX_DNS_MESSAGE) return
            val answer = queryDnsOverTcp(query) ?: return

            val replyPayloadLength = UDPGW_HEADER + addressLength + answer.size
            if (replyPayloadLength > MAX_PACKET_PAYLOAD) return
            val reply = ByteArray(PACKETPROTO_HEADER + replyPayloadLength)
            reply[0] = (replyPayloadLength and 0xff).toByte()
            reply[1] = ((replyPayloadLength ushr 8) and 0xff).toByte()
            reply[2] = if (isIpv6) FLAG_IPV6.toByte() else 0.toByte()
            reply[3] = (connectionId and 0xff).toByte()
            reply[4] = ((connectionId ushr 8) and 0xff).toByte()
            // Preserve the original remote address so tun2socks matches the pending flow.
            System.arraycopy(packet, addressOffset, reply, PACKETPROTO_HEADER + UDPGW_HEADER, addressLength)
            System.arraycopy(answer, 0, reply, payloadOffset, answer.size)

            val responseSocket = socket ?: return
            if (!responseSocket.isClosed) {
                responseSocket.send(DatagramPacket(reply, reply.size, sender))
            }
        } catch (e: Exception) {
            if (!closed.get()) FirefoxLog.w(TAG, "DNS-over-TCP forwarding failed", e)
        }
    }

    private fun queryDnsOverTcp(query: ByteArray): ByteArray? {
        for (host in arrayOf("1.1.1.1", "8.8.8.8")) {
            var stream: TunneledStream? = null
            try {
                stream = runBlocking(Dispatchers.IO) { upstream.openStream(host, DNS_PORT) }
                stream.output.write((query.size ushr 8) and 0xff)
                stream.output.write(query.size and 0xff)
                stream.output.write(query)
                stream.output.flush()

                val high = stream.input.read()
                val low = stream.input.read()
                if (high < 0 || low < 0) throw EOFException("DNS-over-TCP length prefix ended early")
                val length = (high shl 8) or low
                if (length < 12 || length > MAX_DNS_MESSAGE) throw IOException("Invalid DNS response length")
                return readFully(stream.input, length)
            } catch (e: Exception) {
                FirefoxLog.d(TAG, "DNS resolver $host failed: ${e.message}")
            } finally {
                runCatching { stream?.close?.invoke() }
            }
        }
        return null
    }

    private fun readFully(input: java.io.InputStream, length: Int): ByteArray {
        val result = ByteArray(length)
        var offset = 0
        while (offset < length) {
            val count = input.read(result, offset, length - offset)
            if (count < 0) throw EOFException("DNS response ended early")
            if (count == 0) continue
            offset += count
        }
        return result
    }

    private fun u8(value: Byte): Int = value.toInt() and 0xff

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        socket?.close()
        socket = null
        receiver?.interrupt()
        receiver = null
        workers.shutdownNow()
    }

    private companion object {
        const val TAG = "FirefoxDNS"
        const val DEFAULT_PORT = 7300
        const val DNS_PORT = 53
        const val PACKETPROTO_HEADER = 2
        const val UDPGW_HEADER = 3
        const val IPV4_ADDRESS = 6
        const val IPV6_ADDRESS = 18
        const val FLAG_DNS = 1 shl 2
        const val FLAG_IPV6 = 1 shl 3
        const val MAX_PACKET_SIZE = 65535
        const val MAX_PACKET_PAYLOAD = 65535
        const val MAX_DNS_MESSAGE = 65535
    }
}
