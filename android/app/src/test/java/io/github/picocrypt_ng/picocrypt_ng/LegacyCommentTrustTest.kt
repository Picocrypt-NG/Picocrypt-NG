package io.github.picocrypt_ng.picocrypt_ng

import org.json.JSONException
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class LegacyCommentTrustTest {
    @Test
    fun `preview never accepts an authentication claim for any version`() {
        for (version in listOf("v1.49", "v2.00", "v2.19", "v3.00", "", "future")) {
            for (marker in listOf("authenticated", "unverified", "unavailable", "future", "")) {
                val info = parse(version = version, authenticity = marker)
                assertEquals("$version/$marker", CommentAuthenticity.UNVERIFIED, info.commentAuthenticity)
                assertEquals("visible plaintext", info.comments)
                assertTrue(info.readable)
            }
        }
    }

    @Test
    fun `missing and malformed additive metadata retains conservative old preview behavior`() {
        val old = GoBridge.parseDecryptionInfo(preview().toString())
        assertEquals("", old.version)
        assertEquals(CommentAuthenticity.UNVERIFIED, old.commentAuthenticity)
        assertEquals(LegacySecurityWarning.NONE, old.securityWarning)
        for (value in listOf(JSONObject.NULL, 12, true, JSONObject())) {
            val json = preview().put("version", value).put("commentAuthenticity", value).put("securityWarning", value)
            val actual = GoBridge.parseDecryptionInfo(json.toString())
            assertEquals("", actual.version)
            assertEquals(CommentAuthenticity.UNVERIFIED, actual.commentAuthenticity)
            assertEquals(LegacySecurityWarning.NONE, actual.securityWarning)
        }
    }

    @Test
    fun `legacy limitations remain visible independently of comment presence`() {
        for (comment in listOf("visible plaintext", "")) {
            val v1 = parse("v1.49", comments = comment)
            assertEquals(LegacySecurityWarning.UNAUTHENTICATED_V1_HEADER, v1.securityWarning)
            val v2 = parse("v2.19", comments = comment, keyfiles = true)
            assertEquals(LegacySecurityWarning.V2_PASSWORD_ONLY_AUTHENTICATION, v2.securityWarning)
            assertEquals(LegacySecurityWarning.NONE, parse("v2.19", comments = comment).securityWarning)
        }
    }

    @Test
    fun `empty or unreadable comments have no available authenticity`() {
        assertEquals(CommentAuthenticity.UNAVAILABLE, parse("v2.19", "authenticated", comments = "").commentAuthenticity)
        val deniable = GoBridge.parseDecryptionInfo(preview().put("readable", false)
            .put("deniability", true).put("commentAuthenticity", "authenticated").toString())
        assertEquals(CommentAuthenticity.UNAVAILABLE, deniable.commentAuthenticity)
        assertFalse(deniable.readable)
    }

    @Test
    fun `metadata additions never relax required credential or header fields`() {
        for (field in listOf("keyfilesRequired", "keyfileOrdered", "reedSolomon", "deniability", "paranoid", "comments", "readable")) {
            val json = preview().put("version", "v2.19").put("commentAuthenticity", "authenticated")
            json.remove(field)
            assertThrows("missing $field", JSONException::class.java) { GoBridge.parseDecryptionInfo(json.toString()) }
        }
    }

    @Test
    fun `existing constructors cannot silently authenticate preview comments`() {
        val old = DecryptionInfo(false, false, false, false, false, "visible plaintext", true)
        assertEquals(CommentAuthenticity.UNVERIFIED, old.commentAuthenticity)
        assertEquals(CommentAuthenticity.UNAVAILABLE, DecryptionInfo(false, false, false, false, false, "", true).commentAuthenticity)
        assertEquals(R.string.legacy_v1_security_warning, legacySecurityWarningResource(LegacySecurityWarning.UNAUTHENTICATED_V1_HEADER))
        assertEquals(R.string.legacy_v2_security_warning, legacySecurityWarningResource(LegacySecurityWarning.V2_PASSWORD_ONLY_AUTHENTICATION))
        assertNull(legacySecurityWarningResource(LegacySecurityWarning.NONE))
    }

    private fun parse(version: String, authenticity: String = "unverified", comments: String = "visible plaintext", keyfiles: Boolean = false): DecryptionInfo =
        GoBridge.parseDecryptionInfo(preview().put("version", version).put("commentAuthenticity", authenticity)
            .put("comments", comments).put("keyfilesRequired", keyfiles).toString())

    private fun preview(): JSONObject = JSONObject()
        .put("keyfilesRequired", false).put("keyfileOrdered", false).put("reedSolomon", false)
        .put("deniability", false).put("paranoid", false).put("comments", "visible plaintext").put("readable", true)
}
