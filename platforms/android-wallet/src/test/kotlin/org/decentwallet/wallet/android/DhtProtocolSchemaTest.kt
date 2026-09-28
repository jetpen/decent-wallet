package org.decentwallet.wallet.android

import com.google.protobuf.ByteString
import org.decentwallet.wallet.android.dht.proto.Message as DhtMessage
import org.decentwallet.wallet.android.dht.proto.Record
import org.junit.Assert.assertArrayEquals
import org.junit.Test

class DhtProtocolSchemaTest {
    @Test
    fun getValueUsesStandardKadDhtFieldNumbers() {
        val message = DhtMessage.newBuilder()
            .setType(DhtMessage.MessageType.GET_VALUE)
            .setKey(ByteString.copyFromUtf8("abc"))
            .build()

        assertArrayEquals(
            byteArrayOf(0x08, 0x01, 0x12, 0x03, 0x61, 0x62, 0x63),
            message.toByteArray(),
        )
    }

    @Test
    fun putValueUsesStandardRecordNesting() {
        val record = Record.newBuilder()
            .setKey(ByteString.copyFromUtf8("k"))
            .setValue(ByteString.copyFromUtf8("v"))
            .build()
        val message = DhtMessage.newBuilder()
            .setType(DhtMessage.MessageType.PUT_VALUE)
            .setKey(ByteString.copyFromUtf8("k"))
            .setRecord(record)
            .build()

        assertArrayEquals(
            byteArrayOf(0x12, 0x01, 0x6b, 0x1a, 0x06, 0x0a, 0x01, 0x6b, 0x12, 0x01, 0x76),
            message.toByteArray(),
        )
    }
}
