package org.decentwallet.wallet.client

import okhttp3.MediaType
import okhttp3.RequestBody
import okio.BufferedSink

// Keep the payload and wire framing unchanged while suppressing HTTP follow-ups
// that OkHttp may issue even when connection retries are disabled.
internal fun ByteArray.toOneShotRequestBody(mediaType: MediaType): RequestBody = object : RequestBody() {
    override fun contentType(): MediaType = mediaType
    override fun contentLength(): Long = this@toOneShotRequestBody.size.toLong()
    override fun isOneShot(): Boolean = true
    override fun writeTo(sink: BufferedSink) {
        sink.write(this@toOneShotRequestBody)
    }
}