package io.github.picocrypt_ng.picocrypt_ng

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class SecureBytesTest {
    @Test
    fun `large three-byte password retains the final character instead of a float-rounded prefix`() {
        val password = CharArray(5_592_407) { '\u0800' }
        password[password.lastIndex] = '\u0801'
        val encoded = password.toUtf8BytesSecure()
        try {
            assertEquals(16_777_221, encoded.size)
            assertArrayEquals(byteArrayOf(0xe0.toByte(), 0xa0.toByte(), 0x81.toByte()), encoded.takeLast(3).toByteArray())
        } finally { encoded.fill(0); password.fill('\u0000') }
    }

    @Test
    fun `malformed surrogate uses the historical replacement byte`() {
        assertArrayEquals(byteArrayOf(0x41, 0x3f, 0x42), charArrayOf('A', '\ud800', 'B').toUtf8BytesSecure())
    }

    @Test
    fun `ascii password encodes to UTF-8 matching String getBytes`() {
        val pw = "hunter2".toCharArray()
        assertArrayEquals("hunter2".toByteArray(Charsets.UTF_8), pw.toUtf8BytesSecure())
    }

    @Test
    fun `multibyte password matches legacy String UTF-8 path (interop)`() {
        // Locks byte-for-byte compatibility with the desktop/CLI String(password)->UTF-8 path.
        val pw = "pä€🔒".toCharArray() // includes 2-byte, 3-byte, and a surrogate-pair 4-byte char
        assertArrayEquals("pä€🔒".toByteArray(Charsets.UTF_8), pw.toUtf8BytesSecure())
    }

    @Test
    fun `empty password encodes to empty array`() {
        assertArrayEquals(ByteArray(0), CharArray(0).toUtf8BytesSecure())
    }

    @Test
    fun `long multibyte password matches legacy String UTF-8 path (regrow path)`() {
        // 1000 three-byte chars (3000 bytes) exercises the path where the old
        // convenience encoder could internally grow (and orphan) its working
        // buffer. Proves byte-for-byte equivalence on the large/multibyte path.
        val pw = CharArray(1000) { 'あ' }
        assertArrayEquals(String(pw).toByteArray(Charsets.UTF_8), pw.toUtf8BytesSecure())
    }

    @Test
    fun `surrogate-pair password matches legacy String UTF-8 path`() {
        // Repeated 4-byte emoji (each a high+low surrogate pair) confirms
        // worst-case sizing via maxBytesPerChar handles surrogate pairs.
        val pw = "😀".repeat(500).toCharArray()
        assertArrayEquals(String(pw).toByteArray(Charsets.UTF_8), pw.toUtf8BytesSecure())
    }
}
