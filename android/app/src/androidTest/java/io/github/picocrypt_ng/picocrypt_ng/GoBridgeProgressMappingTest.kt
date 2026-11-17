package io.github.picocrypt_ng.picocrypt_ng

import androidx.test.ext.junit.runners.AndroidJUnit4
import mobile.ProgressResult as GoProgressResult
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class GoBridgeProgressMappingTest {
    @Test
    fun commentAuthenticationRequiresCleanV2CompletionAtTheActualGeneratedGetterBoundary() {
        val native = GoProgressResult().apply {
            setStatusCode(OperationStatus.COMPLETED)
            setDone(true)
            setLegacyVersion("v2.19")
            setCommentAuthenticity("authenticated")
            setLegacySecurityWarning("LEGACY_V2_PASSWORD_ONLY_AUTHENTICATION")
        }
        fun mapped() = with(GoBridge) { native.toProgressState() }
        assertEquals(CommentAuthenticity.AUTHENTICATED, mapped().commentAuthenticity)
        assertEquals("v2.19", mapped().legacyVersion)
        assertEquals(LegacySecurityWarning.V2_PASSWORD_ONLY_AUTHENTICATION, mapped().legacySecurityWarning)

        native.setLegacyVersion("v1.49")
        assertEquals(CommentAuthenticity.UNVERIFIED, mapped().commentAuthenticity)
        assertEquals(LegacySecurityWarning.UNAUTHENTICATED_V1_HEADER, mapped().legacySecurityWarning)
        for (version in listOf("", "v3.00", "v2.19suffix", "future")) {
            native.setLegacyVersion(version)
            assertEquals(CommentAuthenticity.UNVERIFIED, mapped().commentAuthenticity)
            assertEquals("", mapped().legacyVersion)
        }
        native.setLegacyVersion("v2.19")
        native.setStatusCode(OperationStatus.COMPLETED_UNVERIFIED)
        assertEquals(CommentAuthenticity.AUTHENTICATED, mapped().commentAuthenticity)
        assertEquals(OperationStatus.COMPLETED_UNVERIFIED, mapped().status.code)
        native.setCommentAuthenticity("unverified")
        assertEquals(CommentAuthenticity.UNVERIFIED, mapped().commentAuthenticity)
        native.setCommentAuthenticity("authenticated")
        for (status in listOf(OperationStatus.ERROR, OperationStatus.CANCELLED, OperationStatus.DECRYPTING_RATE, "future")) {
            native.setStatusCode(status)
            assertEquals(CommentAuthenticity.UNAVAILABLE, mapped().commentAuthenticity)
            assertEquals("", mapped().legacyVersion)
            assertEquals(LegacySecurityWarning.NONE, mapped().legacySecurityWarning)
        }
        native.setStatusCode(OperationStatus.COMPLETED)
        native.setDone(false)
        assertEquals(CommentAuthenticity.UNAVAILABLE, mapped().commentAuthenticity)
        native.setDone(true)
        native.setError("native failure")
        assertEquals(CommentAuthenticity.UNAVAILABLE, mapped().commentAuthenticity)
        native.setError("")
        native.setCode("AUTH_FAILED")
        assertEquals(CommentAuthenticity.UNAVAILABLE, mapped().commentAuthenticity)
        native.setCode("")
        for (marker in listOf("", "future", "unavailable")) {
            native.setCommentAuthenticity(marker)
            assertEquals(CommentAuthenticity.UNAVAILABLE, mapped().commentAuthenticity)
        }
    }

    @Test
    fun gomobileProgressAdapterMapsEveryConsumedNativeField() {
        val result = GoProgressResult().apply {
            setStatusCode("ENCRYPTING_RATE")
            setStatusSpeedMiBPerSecond(12.34)
            setStatusETA("01:02:03")
            setInfoCode("ITEM_COUNT")
            setInfoCurrent(3)
            setInfoTotal(10)
            setProgress(0.5f)
            setDone(true)
            setError("diagnostic only")
            setCode("GENERIC")
        }

        val progressState = with(GoBridge) { result.toProgressState() }

        assertEquals(
            ProgressState(
                status = OperationStatusData(
                    code = "ENCRYPTING_RATE",
                    speedMiBPerSecond = 12.34,
                    eta = "01:02:03",
                ),
                detail = OperationProgressDetail(
                    code = "ITEM_COUNT",
                    current = 3,
                    total = 10,
                ),
                progress = 0.5f,
                done = true,
                technicalError = "diagnostic only",
                errorCode = "GENERIC",
            ),
            progressState,
        )
    }
}
