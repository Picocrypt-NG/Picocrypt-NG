package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import androidx.lifecycle.viewModelScope
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Real JNI + ViewModel teardown smoke; controlled late-ack timing belongs to the JVM lane. */
@RunWith(AndroidJUnit4::class)
class Pcv3InputCustodyDeviceTest {
    @Test
    fun destroyedViewModelLeavesProcessOwnerToSettleStagedInput() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        assertTrue(StartupCleanup.runBeforeUi(context))
        assertTrue(StartupCleanup.allowsPcv3Dispatch())
        val directory = File(context.filesDir, "picocrypt_files/staging/input-custody-${System.nanoTime()}").apply { mkdirs() }
        val source = File(directory, "source.txt").apply { writeText("public custody fixture") }
        val target = File(directory, "output.pcv")
        val model = withContext(Dispatchers.Main) { OperationViewModel() }
        val password = "public test password".toCharArray()
        try {
            withContext(Dispatchers.Main) {
                model.startPcv3(context, Pcv3OperationTransfer(
                    Pcv3OperationIntent(Pcv3FormatIntent.NORMAL, action = Pcv3ActionIntent.CREATE),
                    Pcv3WriteRequest("write-normal", "password", "none", source.path, target.path,
                        emptyList(), "", "standard", false, inputFiles = listOf(source.path)), password,
                ))
            }
            withTimeout(30_000) {
                OperationManager.currentPcv3Presentation.first { it is Pcv3Presentation.Live }
            }
            withContext(Dispatchers.Main) {
                model.viewModelScope.coroutineContext[Job]!!.cancelAndJoin()
            }
            withTimeout(30_000) {
                OperationManager.currentPcv3InputCleanupPending.first { !it }
            }
            assertTrue(password.all { it == '\u0000' })
            assertFalse(source.exists())
            assertNull(OperationManager.currentPcv3InputCleanupFailure.value)
            // A fast native success may precede teardown. Consume retained ciphertext explicitly;
            // exact delayed cancellation timing is proved by the controlled JVM schedule.
            val result = requireNotNull(OperationManager.currentPcv3Presentation.value)
            if (result is Pcv3Presentation.Live && result.outputPending) {
                OperationManager.discardPcv3Output(result.operationId, result.generation).getOrThrow()
            }
            val terminal = requireNotNull(OperationManager.currentPcv3Presentation.value)
            assertTrue("accepted request must release native ownership", terminal is Pcv3Presentation.Final)
            assertTrue(terminal.snapshot.completionClass !in listOf("", "unknown"))
            assertTrue(OperationManager.dismissPcv3(terminal.operationId, terminal.generation))
            assertFalse(target.exists())
        } finally {
            withContext(Dispatchers.Main) { model.viewModelScope.coroutineContext[Job]!!.cancelAndJoin() }
            OperationManager.cancelCurrentPcv3ForHost()
            OperationManager.refreshPcv3()
            OperationManager.currentPcv3Presentation.value?.let { OperationManager.dismissPcv3(it.operationId, it.generation) }
            if (!OperationManager.currentPcv3InputCleanupPending.value && !OperationManager.currentPcv3Busy.value) {
                assertTrue(NoFollowFileTree.delete(context.filesDir, directory))
            }
        }
    }
}
