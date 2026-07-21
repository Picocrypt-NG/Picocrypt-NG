package io.github.picocrypt_ng.picocrypt_ng.ui.components

import android.net.Uri
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.lifecycle.SavedStateHandle
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.AppError
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.cancellation.CancellationException
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NewKeyfileLifecycleTest {
    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun failedCreationRendersExactlyOneGlobalErrorDialog() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val viewModel = MainViewModel(application, SavedStateHandle())
        val sentinel = "sentinel-keyfile-creation-failure"
        val failure = AppError.FileError.SaveFailed(
            userMessage = sentinel,
            messageResId = null,
        )

        composeTestRule.setContent {
            val error by viewModel.errorMessage.collectAsState()
            NewKeyfile(
                viewModel = viewModel,
                initialCreatedUri = Uri.parse("content://picocrypt.test/keyfile"),
                createKeyfile = { _, _ -> Result.failure(failure) },
            )
            ErrorDialog(error = error, onDismiss = viewModel::clearError)
        }

        composeTestRule.waitForIdle()

        assertSame("The global owner must retain the exact failure", failure, viewModel.errorMessage.value)
        composeTestRule.onAllNodes(isDialog()).assertCountEquals(1)
        composeTestRule.onNodeWithText(sentinel).assertIsDisplayed()
        composeTestRule.onAllNodesWithText(sentinel).assertCountEquals(1)
    }

    @Test
    fun thrownCancellationRendersNoErrorDialog() {
        val cancellation = CancellationException("configuration recreation")

        assertCancellationRendersNoError {
            throw cancellation
        }
    }

    @Test
    fun returnedCancellationRendersNoErrorDialog() {
        val cancellation = CancellationException("returned cancellation")

        assertCancellationRendersNoError {
            Result.failure(cancellation)
        }
    }

    private fun assertCancellationRendersNoError(
        operation: suspend () -> Result<String>,
    ) {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val viewModel = MainViewModel(application, SavedStateHandle())
        val invoked = AtomicBoolean(false)

        composeTestRule.setContent {
            val error by viewModel.errorMessage.collectAsState()
            NewKeyfile(
                viewModel = viewModel,
                initialCreatedUri = Uri.parse("content://picocrypt.test/keyfile"),
                createKeyfile = { _, _ ->
                    invoked.set(true)
                    operation()
                },
            )
            ErrorDialog(error = error, onDismiss = viewModel::clearError)
        }

        composeTestRule.waitForIdle()

        assertTrue("Injected creation must execute before assertions", invoked.get())
        assertNull("Cancellation must not enter retained error state", viewModel.errorMessage.value)
        composeTestRule.onAllNodes(isDialog()).assertCountEquals(0)
    }
}
