package org.decentwallet.wallet.android

import com.google.protobuf.ByteString
import io.libp2p.core.Host
import io.libp2p.core.Stream
import io.libp2p.core.crypto.KeyType
import io.libp2p.core.dsl.host as newLibp2pHost
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multistream.StrictProtocolBinding
import io.libp2p.core.mux.StreamMuxerProtocol
import io.libp2p.protocol.ProtobufProtocolHandler
import io.libp2p.protocol.ProtocolMessageHandler
import io.libp2p.security.noise.NoiseXXSecureChannel
import io.libp2p.transport.tcp.TcpTransport
import java.io.IOException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import org.decentwallet.wallet.android.dht.proto.Message as DhtMessage
import org.decentwallet.wallet.android.dht.proto.Record

/** A one-request-per-stream direct Kad-DHT client; it never uses a local DHT value store. */
internal interface AndroidKadDhtRpcClient : AutoCloseable {
    fun getValue(peerMultiaddr: String, key: ByteArray): ByteArray?

    /** True means the peer acknowledged this key; it does not confirm the stored value. */
    fun putValue(peerMultiaddr: String, key: ByteArray, value: ByteArray): Boolean

    override fun close()
}

internal object KadDhtResponses {
    fun isAcceptedPutResponse(response: DhtMessage, requestedKey: ByteArray): Boolean =
        response.type == DhtMessage.MessageType.PUT_VALUE &&
            response.key.toByteArray().contentEquals(requestedKey)
}

/** Uses libp2p TCP + Noise and the standard /ipfs/kad/1.0.0 protobuf stream. */
internal class JvmLibp2pKadDhtRpcClient(
    private val timeoutMillis: Long,
    peerMultiaddrs: List<String>,
) : AndroidKadDhtRpcClient {
    private val closed = AtomicBoolean(false)
    private val addresses = peerMultiaddrs.associateWith(::parsePinnedPeerAddress)
    private val binding = DirectKadDhtBinding()
    private val host: Host = newLibp2pHost {
        identity { random(KeyType.ED25519) }
        transports { add(::TcpTransport) }
        secureChannels { add(::NoiseXXSecureChannel) }
        muxers { add(StreamMuxerProtocol.Mplex) }
        protocols { add(binding) }
        network { listen("/ip4/127.0.0.1/tcp/0") }
    }

    init {
        await(host.start(), "start libp2p host")
    }

    override fun getValue(peerMultiaddr: String, key: ByteArray): ByteArray? {
        require(key.isNotEmpty()) { "DHT key must not be empty" }
        val request = DhtMessage.newBuilder()
            .setType(DhtMessage.MessageType.GET_VALUE)
            .setKey(ByteString.copyFrom(key))
            .build()
        val response = exchange(peerMultiaddr, request)
        requireResponseType(response, DhtMessage.MessageType.GET_VALUE, key)
        if (!response.hasRecord()) return null
        val record = response.record
        if (!record.key.toByteArray().contentEquals(key)) {
            throw IOException("Registry peer returned a record for a different DHT key")
        }
        return record.value.toByteArray()
    }

    override fun putValue(peerMultiaddr: String, key: ByteArray, value: ByteArray): Boolean {
        require(key.isNotEmpty()) { "DHT key must not be empty" }
        val record = Record.newBuilder()
            .setKey(ByteString.copyFrom(key))
            .setValue(ByteString.copyFrom(value))
            .build()
        val request = DhtMessage.newBuilder()
            .setType(DhtMessage.MessageType.PUT_VALUE)
            .setKey(ByteString.copyFrom(key))
            .setRecord(record)
            .build()
        val response = exchange(peerMultiaddr, request)
        if (response.type != DhtMessage.MessageType.PUT_VALUE) {
            throw IOException("Registry peer returned an unexpected Kad-DHT response type")
        }
        return KadDhtResponses.isAcceptedPutResponse(response, key)
    }

    private fun exchange(peerMultiaddr: String, request: DhtMessage): DhtMessage {
        check(!closed.get()) { "Kad-DHT client is closed" }
        val address = addresses[peerMultiaddr]
            ?: throw IllegalArgumentException("peer is not in the pinned Registry peer set")
        try {
            val streamPromise = binding.dial(host, address)
            try {
                val controller = await(streamPromise.controller, "negotiate Kad-DHT stream")
                return await(controller.exchange(request), "complete Kad-DHT RPC")
            } catch (failure: Exception) {
                // Close even a late-created stream after a timed-out negotiation or RPC.
                streamPromise.stream.thenAccept { stream -> stream.close() }
                throw failure
            }
        } catch (failure: Exception) {
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            throw IOException("direct Kad-DHT RPC failed", failure)
        }
    }

    private fun requireResponseType(response: DhtMessage, expectedType: DhtMessage.MessageType, key: ByteArray) {
        if (response.type != expectedType) {
            throw IOException("Registry peer returned an unexpected Kad-DHT response type")
        }
        val responseKey = response.key.toByteArray()
        if (responseKey.isNotEmpty() && !responseKey.contentEquals(key)) {
            throw IOException("Registry peer returned a response for a different DHT key")
        }
    }

    private fun parsePinnedPeerAddress(value: String): Multiaddr {
        val address = try {
            Multiaddr.fromString(value)
        } catch (failure: Exception) {
            throw IllegalArgumentException("invalid Registry peer multiaddr", failure)
        }
        require(address.getPeerId() != null) { "Registry peer multiaddr must pin /p2p/<peer-id>" }
        return address
    }

    private fun <T> await(future: CompletableFuture<T>, operation: String): T = try {
        future.get(timeoutMillis, TimeUnit.MILLISECONDS)
    } catch (failure: InterruptedException) {
        Thread.currentThread().interrupt()
        throw IOException("interrupted while attempting to $operation", failure)
    } catch (failure: ExecutionException) {
        throw IOException("failed to $operation", failure.cause ?: failure)
    } catch (failure: TimeoutException) {
        throw IOException("timed out while attempting to $operation", failure)
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            await(host.stop(), "stop libp2p host")
        }
    }

    private class DirectKadDhtBinding : StrictProtocolBinding<DirectKadDhtController>(
        KAD_DHT_PROTOCOL_ID,
        DirectKadDhtProtocol(),
    )

    private class DirectKadDhtProtocol : ProtobufProtocolHandler<DirectKadDhtController>(
        DhtMessage.getDefaultInstance(),
        MAX_DHT_MESSAGE_BYTES,
        MAX_DHT_MESSAGE_BYTES,
    ) {
        override fun onStartInitiator(stream: Stream): CompletableFuture<DirectKadDhtController> {
            val ready = CompletableFuture<DirectKadDhtController>()
            stream.pushHandler(DirectKadDhtController(ready))
            return ready
        }
    }

    private class DirectKadDhtController(
        private val ready: CompletableFuture<DirectKadDhtController>,
    ) : ProtocolMessageHandler<DhtMessage> {
        private val pending = AtomicReference<CompletableFuture<DhtMessage>?>(null)
        private lateinit var stream: Stream

        override fun onActivated(stream: Stream) {
            this.stream = stream
            ready.complete(this)
        }

        fun exchange(request: DhtMessage): CompletableFuture<DhtMessage> {
            val response = CompletableFuture<DhtMessage>()
            if (!pending.compareAndSet(null, response)) {
                response.completeExceptionally(IllegalStateException("Kad-DHT stream already has a request"))
                return response
            }
            try {
                stream.writeAndFlush(request)
            } catch (failure: Throwable) {
                pending.compareAndSet(response, null)
                response.completeExceptionally(failure)
            }
            return response
        }

        override fun onMessage(stream: Stream, msg: DhtMessage) {
            val response = pending.getAndSet(null)
            if (response == null) {
                stream.close()
                return
            }
            response.complete(msg)
            stream.close()
        }

        override fun onClosed(stream: Stream) {
            pending.getAndSet(null)?.completeExceptionally(IOException("Kad-DHT stream closed before response"))
        }

        override fun onReadClosed(stream: Stream) {
            pending.getAndSet(null)?.completeExceptionally(IOException("Kad-DHT peer closed before response"))
        }

        override fun onException(cause: Throwable?) {
            pending.getAndSet(null)?.completeExceptionally(cause ?: IOException("Kad-DHT stream failed"))
        }
    }

    private companion object {
        const val KAD_DHT_PROTOCOL_ID = "/ipfs/kad/1.0.0"
        const val MAX_DHT_MESSAGE_BYTES = 1_048_576L
    }
}
