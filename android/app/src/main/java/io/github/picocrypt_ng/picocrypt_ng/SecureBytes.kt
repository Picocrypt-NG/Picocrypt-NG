package io.github.picocrypt_ng.picocrypt_ng

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction

/**
 * Encodes this CharArray to UTF-8 bytes without ever creating a String (which
 * would be an immutable, un-zeroable JVM object that survives in heap dumps).
 * The transient backing buffer is zeroed before returning. The returned array
 * is owned by the caller and must be zeroed after use.
 *
 * Malformed input uses the historical replacement byte by default. PCV3 requests
 * REPORT so malformed UTF-16 is refused before the native call.
 */
internal fun CharArray.toUtf8BytesSecure(errorAction: CodingErrorAction = CodingErrorAction.REPLACE): ByteArray {
    val input = CharBuffer.wrap(this)
    val encoder = Charsets.UTF_8.newEncoder()
        .onMalformedInput(errorAction)
        .onUnmappableCharacter(errorAction)
    val buffer = ByteBuffer.allocate(Math.multiplyExact(size, 3))
    try {
        val encoded = encoder.encode(input, buffer, true)
        if (encoded.isError) encoded.throwException()
        check(encoded.isUnderflow && !input.hasRemaining()) { "Incomplete UTF-8 password encoding" }
        val flushed = encoder.flush(buffer)
        if (flushed.isError) flushed.throwException()
        check(flushed.isUnderflow) { "Incomplete UTF-8 password flush" }
        buffer.flip()
        return ByteArray(buffer.remaining()).also(buffer::get)
    } finally {
        buffer.array().fill(0)
    }
}

// Legacy volumes may have been written with a float-rounded password prefix.
// Preserve that exact representation only in the explicit legacy reader.
internal fun CharArray.toLegacyUtf8BytesSecure(): ByteArray {
    val charBuffer = CharBuffer.wrap(this)
    val encoder = Charsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPLACE)
        .onUnmappableCharacter(CodingErrorAction.REPLACE)
    val maxBytes = (charBuffer.remaining() * encoder.maxBytesPerChar()).toInt()
    val byteBuffer = ByteBuffer.allocate(maxBytes) // single buffer we own; no internal regrow
    try {
        encoder.encode(charBuffer, byteBuffer, true)
        encoder.flush(byteBuffer)
        byteBuffer.flip()
        return ByteArray(byteBuffer.remaining()).also(byteBuffer::get)
    } finally {
        byteBuffer.array().fill(0)
    }
}
