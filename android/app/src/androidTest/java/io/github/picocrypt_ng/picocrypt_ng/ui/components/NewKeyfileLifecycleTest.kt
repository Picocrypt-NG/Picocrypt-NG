package io.github.picocrypt_ng.picocrypt_ng.ui.components

import android.net.Uri
import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.AppError
import io.github.picocrypt_ng.picocrypt_ng.KeyfileInfo
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.R
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
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
    fun clearQueuedForMutationSurvivesLeavingCompositionAndViewModelClear() = runBlocking {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val viewModelStore = ViewModelStore()
        val viewModelOwner = object : ViewModelStoreOwner {
            override val viewModelStore = viewModelStore
        }
        val viewModel = ViewModelProvider(
            viewModelOwner,
            object : ViewModelProvider.Factory {
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    assertEquals(MainViewModel::class.java, modelClass)
                    @Suppress("UNCHECKED_CAST")
                    return MainViewModel(application, SavedStateHandle()) as T
                }
            },
        )[MainViewModel::class.java]
        val internalDir = File(application.filesDir, "picocrypt_files")
        internalDir.deleteRecursively()
        assertTrue("Internal directory should be created for test setup", internalDir.mkdirs())
        val existingFile = File(internalDir, "keyfile_0").apply { writeBytes(byteArrayOf(1)) }
        val existingInfo = KeyfileInfo(existingFile.absolutePath, "existing.bin")
        viewModel.updateFormData(
            viewModel.formState.value.copy(keyfileFilenames = listOf(existingInfo))
        )
        val mutationAcquired = CompletableDeferred<Unit>()
        val releaseMutation = CompletableDeferred<Unit>()
        val mutationOwner = launch(Dispatchers.Default) {
            withKeyfileMutation {
                mutationAcquired.complete(Unit)
                releaseMutation.await()
            }
        }
        var showClear by mutableStateOf(true)

        try {
            mutationAcquired.await()
            composeTestRule.setContent {
                if (showClear) {
                    ClearKeyfiles(viewModel)
                }
            }

            composeTestRule.onNodeWithText(application.getString(R.string.clear)).performClick()
            composeTestRule.waitForIdle()
            assertTrue(
                "Clear must wait while another keyfile mutation owns the coordinator",
                existingFile.exists(),
            )

            composeTestRule.runOnIdle { showClear = false }
            composeTestRule.waitForIdle()
            viewModelStore.clear()
            releaseMutation.complete(Unit)

            composeTestRule.waitUntil(timeoutMillis = 5_000) {
                viewModel.formState.value.keyfileFilenames.isEmpty() && !existingFile.exists()
            }

            assertTrue(
                "An accepted Clear action must remove the file after its UI and ViewModel are cleared",
                !existingFile.exists(),
            )
            assertTrue(
                "An accepted Clear action must clear its retained form reference",
                viewModel.formState.value.keyfileFilenames.isEmpty(),
            )
        } finally {
            releaseMutation.complete(Unit)
            mutationOwner.cancelAndJoin()
            viewModelStore.clear()
            internalDir.deleteRecursively()
        }
    }

    @Test
    fun clearQueuedDuringCreationRunsAfterTheKeyfileCommit() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val viewModel = MainViewModel(application, SavedStateHandle())
        val internalDir = File(application.filesDir, "picocrypt_files").apply { mkdirs() }
        val existingFile = File(internalDir, "keyfile_0").apply { writeBytes(byteArrayOf(1)) }
        val createdFile = File(internalDir, "keyfile_1")
        val existingInfo = KeyfileInfo(existingFile.absolutePath, "existing.bin")
        viewModel.updateFormData(
            viewModel.formState.value.copy(keyfileFilenames = listOf(existingInfo))
        )
        val creationStarted = CompletableDeferred<Unit>()
        val allowCreationToFinish = CompletableDeferred<Unit>()
        val creationReturned = AtomicBoolean(false)

        try {
            composeTestRule.setContent {
                Column {
                    NewKeyfile(
                        viewModel = viewModel,
                        initialCreatedUri = Uri.parse("content://picocrypt.test/keyfile"),
                        createKeyfile = { _, _ ->
                            creationStarted.complete(Unit)
                            allowCreationToFinish.await()
                            createdFile.writeBytes(byteArrayOf(2))
                            creationReturned.set(true)
                            Result.success(createdFile.absolutePath)
                        },
                    )
                    ClearKeyfiles(viewModel)
                }
            }
            composeTestRule.waitUntil(timeoutMillis = 5_000) { creationStarted.isCompleted }

            composeTestRule.onNodeWithText(application.getString(R.string.clear)).performClick()
            composeTestRule.waitForIdle()
            assertEquals(
                "Clear must wait instead of racing an in-flight creation commit",
                listOf(existingInfo),
                viewModel.formState.value.keyfileFilenames,
            )

            allowCreationToFinish.complete(Unit)
            composeTestRule.waitUntil(timeoutMillis = 5_000) {
                creationReturned.get() &&
                    viewModel.formState.value.keyfileFilenames.isEmpty() &&
                    !existingFile.exists() &&
                    !createdFile.exists()
            }

            assertTrue("The linearly later Clear action must win", viewModel.formState.value.keyfileFilenames.isEmpty())
            assertTrue("Clear must remove the previously registered keyfile", !existingFile.exists())
            assertTrue("Clear must remove the newly committed keyfile", !createdFile.exists())
        } finally {
            allowCreationToFinish.complete(Unit)
            internalDir.deleteRecursively()
        }
    }

    @Test
    fun failedClearPreservesKeyfileReferencesAndSurfacesDeleteError() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val viewModel = MainViewModel(application, SavedStateHandle())
        val existingInfo = KeyfileInfo("/internal/keyfile_0", "existing.bin")
        viewModel.updateFormData(
            viewModel.formState.value.copy(keyfileFilenames = listOf(existingInfo))
        )
        val cleanupCalled = AtomicBoolean(false)

        composeTestRule.setContent {
            ClearKeyfiles(
                viewModel = viewModel,
                cleanupKeyfiles = {
                    cleanupCalled.set(true)
                    false
                },
            )
        }

        composeTestRule.onNodeWithText(application.getString(R.string.clear)).performClick()
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            cleanupCalled.get() && viewModel.errorMessage.value != null
        }

        assertEquals(
            "A failed cleanup must preserve the references needed for a retry",
            listOf(existingInfo),
            viewModel.formState.value.keyfileFilenames,
        )
        val error = viewModel.errorMessage.value
        assertTrue("Cleanup failure must surface as DeleteFailed", error is AppError.FileError.DeleteFailed)
        assertEquals(R.string.error_delete_failed, error?.messageResId)
    }

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
