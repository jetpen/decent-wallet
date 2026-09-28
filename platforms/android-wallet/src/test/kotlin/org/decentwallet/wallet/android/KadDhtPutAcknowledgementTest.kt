package org.decentwallet.wallet.android

import com.google.protobuf.ByteString
import org.decentwallet.wallet.android.dht.proto.Message as DhtMessage
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KadDhtPutAcknowledgementTest {
    @Test
    fun onlyMatchingPutResponseKeyCountsAsAcknowledgement() {
        val key = byteArrayOf(1, 2, 3)
        val wrongKey = byteArrayOf(4, 5, 6)
        val emptyResponse = DhtMessage.newBuilder()
            .setType(DhtMessage.MessageType.PUT_VALUE)
            .build()
        val mismatchedResponse = DhtMessage.newBuilder()
            .setType(DhtMessage.MessageType.PUT_VALUE)
            .setKey(ByteString.copyFrom(wrongKey))
            .build()
        val matchingResponse = DhtMessage.newBuilder()
            .setType(DhtMessage.MessageType.PUT_VALUE)
            .setKey(ByteString.copyFrom(key))
            .build()

        assertFalse(KadDhtResponses.isAcceptedPutResponse(emptyResponse, key))
        assertFalse(KadDhtResponses.isAcceptedPutResponse(mismatchedResponse, key))
        assertTrue(KadDhtResponses.isAcceptedPutResponse(matchingResponse, key))
    }
}
