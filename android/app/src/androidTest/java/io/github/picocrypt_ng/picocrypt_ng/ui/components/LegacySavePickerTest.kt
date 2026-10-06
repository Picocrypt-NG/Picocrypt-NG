package io.github.picocrypt_ng.picocrypt_ng.ui.components

import android.app.Application
import android.net.Uri
import android.os.SystemClock
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.core.app.ActivityOptionsCompat
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.OperationManager
import io.github.picocrypt_ng.picocrypt_ng.OperationState
import io.github.picocrypt_ng.picocrypt_ng.OperationStatus
import io.github.picocrypt_ng.picocrypt_ng.OperationStatusData
import io.github.picocrypt_ng.picocrypt_ng.OperationType
import io.github.picocrypt_ng.picocrypt_ng.OperationViewModel
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import java.io.File
import java.util.UUID
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class LegacySavePickerTest {
    @get:Rule
    val compose = createComposeRule()

    @Test
    fun delayedPickerCannotExportOrDeleteTheReplacementOperation() {
        val app = ApplicationProvider.getApplicationContext<Application>()
        val root = File(app.filesDir, "legacy-picker-${UUID.randomUUID()}")
        assertTrue(root.mkdir())
        val oldInput = File(root, "old-input").apply { writeText("original A") }
        val oldOutput = File(root, "old-output").apply { writeText("result A") }
        val newInput = File(root, "new-input").apply { writeText("original B") }
        val newOutput = File(root, "new-output").apply { writeText("private result B") }
        val wrongDestination = File(root, "destination-selected-for-A")
        val rightDestination = File(root, "destination-selected-for-B")
        val expected = newOutput.readBytes()
        val states = operationStates()
        val original = states.value
        val oldOperation = completed("picker-A", oldInput, oldOutput)
        val newOperation = completed("picker-B", newInput, newOutput)
        val store = ViewModelStore()
        val provider = ViewModelProvider(store, object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T = when (modelClass) {
                MainViewModel::class.java -> MainViewModel(app, SavedStateHandle()) as T
                OperationViewModel::class.java -> OperationViewModel() as T
                else -> error("Unexpected ViewModel")
            }
        })
        val main = provider[MainViewModel::class.java]
        val operation = provider[OperationViewModel::class.java]
        val registry = DelayedPickerRegistry()
        val restoration = StateRestorationTester(compose)
        val owner = object : ActivityResultRegistryOwner {
            override val activityResultRegistry = registry
        }
        try {
            states.value = oldOperation
            restoration.setContent {
                CompositionLocalProvider(LocalActivityResultRegistryOwner provides owner) {
                    ProgressCard(main, operation)
                }
            }
            compose.onNodeWithText(app.getString(R.string.save)).performClick()
            compose.runOnIdle {
                assertEquals(1, registry.launches)
                states.value = newOperation
            }
            compose.waitForIdle()
            compose.runOnIdle { registry.deliver(Uri.fromFile(wrongDestination)) }

            // The production copy uses Dispatchers.IO. Observe the forbidden effects
            // over a bounded real-time window, rather than assuming Compose idle joins it.
            val deadline = SystemClock.uptimeMillis() + 2_000
            do {
                compose.waitForIdle()
                assertFalse("A's picker must not export B's plaintext", wrongDestination.exists())
                assertEquals("A's picker must not clear B", "picker-B", states.value?.id)
                assertEquals("original B", newInput.readText())
                assertArrayEquals(expected, newOutput.readBytes())
                SystemClock.sleep(20)
            } while (SystemClock.uptimeMillis() < deadline)
            assertEquals("original A", oldInput.readText())
            assertEquals("result A", oldOutput.readText())

            // A valid subsequent picker must still copy the exact bytes and settle
            // through real FileCopyService/ContentResolver and operation cleanup.
            compose.onNodeWithText(app.getString(R.string.save)).performClick()
            restoration.emulateSavedInstanceStateRestore()
            compose.runOnIdle {
                assertEquals(2, registry.launches)
                registry.deliver(Uri.fromFile(rightDestination))
            }
            compose.waitUntil(timeoutMillis = 10_000) { states.value == null }
            assertArrayEquals(expected, rightDestination.readBytes())
            assertFalse(newInput.exists())
            assertFalse(newOutput.exists())
            assertFalse(wrongDestination.exists())
            assertEquals("original A", oldInput.readText())
            assertEquals("result A", oldOutput.readText())
        } finally {
            compose.runOnIdle {
                states.value = original
                store.clear()
            }
            root.deleteRecursively()
        }
    }

    private fun completed(id: String, input: File, output: File): OperationState =
        TestDataBuilders.createOperationState(
            id = id,
            type = OperationType.DECRYPT,
            inputFile = input.path,
            outputFile = output.path,
            status = OperationStatusData(OperationStatus.COMPLETED),
            done = true,
        )

    @Suppress("UNCHECKED_CAST")
    private fun operationStates(): MutableStateFlow<OperationState?> =
        OperationManager::class.java.getDeclaredField("_currentOperation").let {
            it.isAccessible = true
            it.get(OperationManager) as MutableStateFlow<OperationState?>
        }

    private class DelayedPickerRegistry : ActivityResultRegistry() {
        private var pendingCode: Int? = null
        var launches = 0
            private set

        override fun <I, O> onLaunch(
            requestCode: Int,
            contract: ActivityResultContract<I, O>,
            input: I,
            options: ActivityOptionsCompat?,
        ) {
            check(pendingCode == null)
            pendingCode = requestCode
            launches++
        }

        fun deliver(uri: Uri?) {
            val code = checkNotNull(pendingCode)
            pendingCode = null
            check(dispatchResult(code, uri))
        }
    }
}
