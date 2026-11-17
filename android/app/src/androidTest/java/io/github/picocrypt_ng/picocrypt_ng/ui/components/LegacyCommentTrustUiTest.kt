package io.github.picocrypt_ng.picocrypt_ng.ui.components

import android.app.Application
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.lifecycle.SavedStateHandle
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.GoBridge
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class LegacyCommentTrustUiTest {
    @get:Rule val compose = createComposeRule()

    @Test
    fun commentsCardLabelsPreviewUnverifiedEvenWhenWireClaimsAuthentication() {
        val app = ApplicationProvider.getApplicationContext<Application>()
        val viewModel = previewViewModel(app, "v2.00", "authenticated")
        compose.setContent { CommentsCard(viewModel) }

        compose.onNodeWithText(app.getString(R.string.comments_unverified)).assertIsDisplayed()
        compose.onNodeWithText("Public preview comment").assertIsDisplayed()
        compose.onNodeWithText(app.getString(R.string.comments_plaintext_warning)).assertIsDisplayed()
        compose.onNodeWithText(app.getString(R.string.legacy_v2_security_warning)).assertIsDisplayed()
        compose.onNodeWithText(app.getString(R.string.comment_authenticity_authenticated)).assertDoesNotExist()
    }

    @Test
    fun decryptionInfoCardLabelsLegacyV1CommentUnverifiedAndExplainsFormatLimit() {
        val app = ApplicationProvider.getApplicationContext<Application>()
        val viewModel = previewViewModel(app, "v1.49", "unverified")
        compose.setContent {
            Column(Modifier.verticalScroll(rememberScrollState())) { DecryptionInfoCard(viewModel) }
        }
        compose.onNodeWithText(app.getString(R.string.encryption_settings)).performClick()

        compose.onNodeWithText(app.getString(R.string.comments_unverified)).performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("Public preview comment").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText(app.getString(R.string.comments_plaintext_warning)).performScrollTo().assertIsDisplayed()
        compose.onNodeWithText(app.getString(R.string.legacy_v1_security_warning)).performScrollTo().assertIsDisplayed()
    }

    private fun previewViewModel(app: Application, version: String, authenticity: String): MainViewModel {
        val info = GoBridge.parseDecryptionInfo("""{
            "keyfilesRequired":true,"keyfileOrdered":false,"reedSolomon":false,
            "deniability":false,"paranoid":false,"comments":"Public preview comment","readable":true,
            "version":"$version","commentAuthenticity":"$authenticity"
        }""")
        return MainViewModel(app, SavedStateHandle()).apply {
            updateFormData(TestDataBuilders.createDecryptFormData(decryptionInfo = info).copy(comments = info.comments))
        }
    }
}
