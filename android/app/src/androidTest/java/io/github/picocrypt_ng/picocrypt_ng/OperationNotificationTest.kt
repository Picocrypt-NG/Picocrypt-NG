package io.github.picocrypt_ng.picocrypt_ng

import android.app.Notification
import android.content.Context
import android.content.res.Configuration
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class OperationNotificationTest {
    @Test
    fun notificationUsesFinalLocalizedRateTextInsteadOfWireCode() {
        val context = localeContext(Locale.FRENCH)
        val status = OperationStatusData(
            code = OperationStatus.ENCRYPTING_RATE,
            speedMiBPerSecond = 12.34,
            eta = "100:59:59",
        )

        val notification = buildOperationNotification(
            context = context,
            type = OperationType.ENCRYPT,
            status = status,
            detail = OperationProgressDetail(OperationProgress.NONE),
            progress = 0.5f,
        )
        val finalText = notification.extras
            .getCharSequence(Notification.EXTRA_TEXT)
            ?.toString()

        assertEquals(
            context.getString(R.string.status_encrypting_rate, 12.34, "100:59:59"),
            finalText,
        )
        assertFalse(
            "The final notification must not expose the gomobile wire code",
            finalText.orEmpty().contains(OperationStatus.ENCRYPTING_RATE),
        )
    }

    @Test
    fun notificationUsesKoreanResourcesForEncryptionTitleAndRateText() {
        val koreanContext = localeContext(Locale.KOREAN)
        val englishContext = localeContext(Locale.ENGLISH)
        val speedMiBPerSecond = 12.34
        val eta = "100:59:59"

        val notification = buildOperationNotification(
            context = koreanContext,
            type = OperationType.ENCRYPT,
            status = OperationStatusData(
                code = OperationStatus.ENCRYPTING_RATE,
                speedMiBPerSecond = speedMiBPerSecond,
                eta = eta,
            ),
            detail = OperationProgressDetail(OperationProgress.NONE),
            progress = 0.5f,
        )
        val finalTitle = notification.extras
            .getCharSequence(Notification.EXTRA_TITLE)
            ?.toString()
        val finalText = notification.extras
            .getCharSequence(Notification.EXTRA_TEXT)
            ?.toString()
        val koreanTitle = koreanContext.getString(R.string.fgs_encrypting)
        val koreanText = koreanContext.getString(
            R.string.status_encrypting_rate,
            speedMiBPerSecond,
            eta,
        )

        assertEquals(koreanTitle, finalTitle)
        assertEquals(koreanText, finalText)
        assertNotEquals(
            englishContext.getString(R.string.fgs_encrypting),
            finalTitle,
        )
        assertNotEquals(
            englishContext.getString(
                R.string.status_encrypting_rate,
                speedMiBPerSecond,
                eta,
            ),
            finalText,
        )
        assertTrue(
            "The Korean title must come from values-ko rather than English fallback",
            finalTitle.orEmpty().contains("암호화"),
        )
        assertFalse(
            "The notification must not expose the gomobile wire code",
            listOf(finalTitle, finalText)
                .filterNotNull()
                .any { it.contains(OperationStatus.ENCRYPTING_RATE) },
        )
    }

    @Test
    fun notificationHidesUnknownRawStatusBehindLocalizedWorkingText() {
        val context = localeContext(Locale.FRENCH)
        val rawSentinel = "raw-backend-status-sentinel"

        val notification = buildOperationNotification(
            context = context,
            type = null,
            status = OperationStatusData(rawSentinel),
            detail = OperationProgressDetail(OperationProgress.NONE),
            progress = 0f,
        )
        val finalText = notification.extras
            .getCharSequence(Notification.EXTRA_TEXT)
            ?.toString()

        assertEquals(context.getString(R.string.fgs_working), finalText)
        assertFalse(
            "Unknown backend text must remain diagnostic rather than user-facing",
            finalText.orEmpty().contains(rawSentinel),
        )
    }

    private fun localeContext(locale: Locale): Context {
        val application = ApplicationProvider.getApplicationContext<Context>()
        val configuration = Configuration(application.resources.configuration).apply {
            setLocale(locale)
        }
        return application.createConfigurationContext(configuration)
    }
}
