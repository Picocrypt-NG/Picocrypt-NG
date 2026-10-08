package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.os.Debug
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Production JNI/lifecycle and a real test-only DocumentsProvider; fixed KDF, real device facts. */
@RunWith(AndroidJUnit4::class)
class Pcv3BoundedSafDeviceTest {
    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before
    fun requireExplicitLargeResourceLane() {
        assumeTrue("opt-in real SAF resource lane; requires frozen host fixtures",
            InstrumentationRegistry.getArguments().getString("boundedResources") == "true")
    }

    @Test
    fun aboveOldEntryLimitPublishesEveryDistinctBodyThroughSaf() = runBlocking {
        exercise("large", 65_537, Int.MAX_VALUE, false, "bounded-saf-65537.pcv")
    }

    @Test
    fun archiveAboveOldMetadataLimitPublishesByteExactlyThroughSaf() = runBlocking {
        exercise("metadata", 513, Int.MAX_VALUE, false, "bounded-saf-metadata.pcv")
    }

    @Test
    fun providerFailurePreservesSourcesAndReportsUncertainPartialPublication() = runBlocking {
        exercise("provider-failure", 257, 32, false)
    }

    @Test
    fun cancellationDuringFreshPreparationObservationStopsBeforeProviderEffects() = runBlocking {
        exercise("cancel-preparation", 257, Int.MAX_VALUE, true)
    }

    @Test
    fun realProviderLongIdentitiesExhaustHostBudgetWithoutLosingSourceOrReceipt() = runBlocking {
        exercise("long-provider-ids", 2048, Int.MAX_VALUE, false, longIDs = true)
    }

    private suspend fun exercise(label: String, count: Int, failAfter: Int, cancelPreparation: Boolean, fixtureName: String? = null, longIDs: Boolean = false) = withContext(Dispatchers.IO) {
        val directory = Files.createTempDirectory(context.cacheDir.toPath(), "pcv3-bounded-$label-").toFile()
        val payload = File(directory, "payload")
        val ciphertext = File(directory, "saved.pcv")
        val target = File(directory, "plaintext.zip")
        val receipt = File(directory, "receipt.json")
        val lifecycle = Pcv3Lifecycle(GoBridge.pcv3Bridge)
        val observer = Pcv3AndroidResourceObservationReader(context)
        val preparing = AtomicBoolean(false)
        val observations = AtomicInteger()
        val entered = CountDownLatch(1)
        val continueObservation = CountDownLatch(1)
        var providerReady = false
        var settled = false
        try {
            if (fixtureName == null) {
                assertTrue(payload.mkdir())
                repeat(count) { index ->
                    File(payload, "f${index.toString().padStart(6, '0')}").writeText("record-$index\n")
                }
            }
            providerCall("reset", Bundle().apply {
                putInt("failAfter", failAfter)
                putInt("idPaddingBytes", if (longIDs) 40_000 else 0)
            })
            providerReady = true
            recordMemory(label, "before-crypto")
            if (fixtureName != null) {
                // Desktop-produced public fixture: Android creation's 4096-path
                // request contract is intentionally not bypassed or raised.
                val fixture = File(context.filesDir, fixtureName)
                assertTrue("host must install the production-facade fixture", fixture.isFile)
                fixture.copyTo(ciphertext)
            } else {
                createArchive(payload, File(directory, "encrypted-stage.pcv"), ciphertext)
            }
            recordMemory(label, "after-creation-before-read")
            val originalHash = digest(ciphertext)
            val originalIdentity = Os.stat(ciphertext.path).let { it.st_dev to it.st_ino }
            lifecycle.start(
                Pcv3Request("read-normal", "password", "none", ciphertext.path, target.path, emptyList()),
                "public bounded SAF fixture".toCharArray(), receipt,
            ).getOrThrow()
            assertTrue(lifecycle.installResourceObservationReader(Pcv3ResourceObservationReader {
                if (preparing.get()) {
                    observations.incrementAndGet()
                    entered.countDown()
                    if (cancelPreparation) check(continueObservation.await(10, TimeUnit.SECONDS))
                }
                observer.read()
            }))
            val completed = withTimeout<Pcv3Presentation>(180_000) {
                while (true) {
                    val current = lifecycle.refreshPcv3().getOrThrow()
                    if (current.snapshot.completionClass != "unknown") return@withTimeout current
                    delay(20)
                }
                error("unreachable")
            }
            recordMemory(label, "after-read")
            assertTrue("authenticated archive must retain a live capability; actual ${completed.javaClass.simpleName}: ${completed.snapshot}",
                completed is Pcv3Presentation.Live)
            val live = completed as Pcv3Presentation.Live
            assertEquals("archive must be authenticated: ${live.snapshot.diagnostic}", "archive-pending", live.snapshot.completionClass)
            assertTrue(live.snapshot.archivePending)
            assertFalse("archive plaintext must remain private", target.exists())
            recordMemory(label, "before-preparation")
            preparing.set(true)
            val publisher = Pcv3SafArchiveProvider(AndroidPcv3SafPlatform(context.contentResolver))
            var publishedEntries = 0
            val measuredPublisher = object : Pcv3SafPublisher {
                override fun newCancellation() = publisher.newCancellation()
                override fun publish(root: Uri, manifest: Pcv3SafManifest, session: Pcv3SafEntrySession, cancellation: Pcv3SafCancellation): Pcv3SafPublicationResult {
                    publishedEntries = manifest.entries.size
                    recordMemory(label, "manifest-captured", publishedEntries)
                    return publisher.publish(root, manifest, object : Pcv3SafEntrySession {
                        override fun attempt(index: Long): Pcv3ArchiveStepData {
                            if (index % (if (longIDs) 128 else 4096) == 0L) recordMemory(label, "provider-$index", publishedEntries)
                            return session.attempt(index)
                        }
                        override fun ackDirectory(index: Long) = session.ackDirectory(index)
                        override fun writeFd(index: Long, descriptor: Long): Pcv3ArchiveStepData {
                            if (index == 1L) {
                                val fdFacts = runCatching {
                                    ParcelFileDescriptor.fromFd(descriptor.toInt()).use { duplicate ->
                                        val stat = Os.fstat(duplicate.fileDescriptor)
                                        val flags = Os.fcntlInt(duplicate.fileDescriptor, OsConstants.F_GETFL, 0)
                                        "mode=${stat.st_mode} size=${stat.st_size} flags=$flags"
                                    }
                                }.getOrElse { "${it.javaClass.simpleName}: ${it.message}" }
                                InstrumentationRegistry.getInstrumentation().sendStatus(2, Bundle().apply {
                                    putString("bounded_saf_first_fd", fdFacts)
                                })
                            }
                            return try {
                                session.writeFd(index, descriptor).also { step ->
                                    if (step.kind != "ready" || step.nextIndex != index + 1) {
                                        InstrumentationRegistry.getInstrumentation().sendStatus(2, Bundle().apply {
                                            putString("bounded_saf_write_failure", "index=$index step=$step")
                                        })
                                    }
                                }
                            } catch (failure: Throwable) {
                                InstrumentationRegistry.getInstrumentation().sendStatus(2, Bundle().apply {
                                    putString("bounded_saf_write_failure", "index=$index ${failure.javaClass.simpleName}: ${failure.message}")
                                })
                                throw failure
                            }
                        }
                    }, cancellation)
                }
            }
            val started = SystemClock.elapsedRealtime()
            val exported = async(Dispatchers.IO) {
                lifecycle.exportPcv3Archive(live.operationId, live.generation, BoundedSafDocumentsProvider.tree, measuredPublisher)
            }
            if (cancelPreparation) {
                assertTrue("real BeginSAF must request a fresh observation", entered.await(10, TimeUnit.SECONDS))
                val cancelled = async(Dispatchers.IO) { lifecycle.cancelPcv3(lifecycle.presentation.value!!.operationId, lifecycle.presentation.value!!.generation) }
                // Native cancellation must settle even while its observation
                // callback is blocked; elapsed time alone proves no ordering.
                withTimeout(3_000) {
                    while (live.operationHandle.snapshot().diagnostic != "cancellation") delay(5)
                }
                continueObservation.countDown()
                withTimeout(10_000) { cancelled.await().getOrThrow() }
            }
            val result = withTimeout(1_800_000) { exported.await() }
            val elapsed = SystemClock.elapsedRealtime() - started
            assertTrue("native preparation pump must submit real fresh facts", observations.get() > 0)
            assertTrue("lifecycle must release native ownership", lifecycle.presentation.value is Pcv3Presentation.Final)
            val terminal = requireNotNull(lifecycle.presentation.value).snapshot
            settled = true
            val verified = providerCall("verify", Bundle().apply {
                putInt("expectedCount", count)
                putBoolean("allowEmpty", longIDs)
            })
            val verifiedCounts = "files=${verified.getInt("files")} invalid=${verified.getInt("invalid")} " +
                "empty=${verified.getInt("empty")} creations=${verified.getInt("creations")} " +
                "firstInvalid=${verified.getString("firstInvalid")}"
            val resultDiagnostic = "result=${result.exceptionOrNull()} terminal=$terminal $verifiedCounts"
            InstrumentationRegistry.getInstrumentation().sendStatus(2, Bundle().apply {
                putString("bounded_saf_result", resultDiagnostic)
            })
            assertTrue(verified.getBoolean("foreignPreserved"))
            assertTrue(verified.getBoolean("onlyExpectedRoots"))
            assertEquals(resultDiagnostic, 0, verified.getInt("invalid"))
            assertEquals(originalHash, digest(ciphertext))
            assertEquals(originalIdentity, Os.stat(ciphertext.path).let { it.st_dev to it.st_ino })
            if (payload.exists()) repeat(count) { index ->
                assertEquals("record-$index\n", File(payload, "f${index.toString().padStart(6, '0')}").readText())
            }
            assertFalse("no published or residual private plaintext", target.exists())
            assertEquals("only caller files and optional terminal receipt remain", emptyList<String>(),
                directory.listFiles().orEmpty().filter { it != payload && it != ciphertext && it != receipt }.map { it.name })
            when {
                cancelPreparation -> {
                    assertEquals(0, publishedEntries)
                    assertEquals(0, verified.getInt("creations"))
                    assertEquals("cancellation", terminal.diagnostic)
                    assertEquals("refused", terminal.completionClass)
                    assertTrue("preparation cancellation must settle promptly", elapsed < 10_000)
                }
                longIDs -> {
                    assertEquals("PCV3_RESOURCE_LIMIT", (result.exceptionOrNull() as? Pcv3BridgeFailure)?.code)
                    assertTrue(verified.getInt("files") in 2 until count)
                    assertEquals("only the newly created, unadmitted document remains empty", 1, verified.getInt("empty"))
                    assertEquals("publication-indeterminate", terminal.publication.state)
                    assertTrue("resource refusal after provider effects must retain the terminal receipt", receipt.isFile)
                }
                failAfter != Int.MAX_VALUE -> {
                    assertTrue(result.isFailure)
                    assertEquals(32, verified.getInt("creations"))
                    assertEquals(31, verified.getInt("files"))
                    assertEquals("publication-indeterminate", terminal.publication.state)
                    assertTrue("partial provider publication must retain a deny-only receipt", receipt.isFile)
                }
                else -> {
                    result.getOrThrow()
                    assertEquals(count + 1, publishedEntries)
                    assertEquals(count, verified.getInt("files"))
                    assertEquals(count + 1, verified.getInt("creations"))
                    // SAF confirms writes and close, not the remote provider's crash durability.
                    assertEquals("published-durability-uncertain", terminal.publication.state)
                }
            }
            recordMemory(label, "settled", publishedEntries, elapsed)
        } finally {
            continueObservation.countDown()
            if (!settled) runCatching { withTimeout(10_000) { lifecycle.cancelCurrentPcv3ForHost() } }
            if (providerReady) assertTrue(providerCall("cleanup").getBoolean("cleaned"))
            assertTrue("test-owned workspace cleanup", directory.deleteRecursively())
        }
    }

    private suspend fun createArchive(payload: File, target: File, saved: File) {
        val password = "public bounded SAF fixture".toCharArray()
        val paths = payload.listFiles().orEmpty().sortedBy { it.name }.map { it.path }
        val start = GoBridge.pcv3Bridge.start(Pcv3WriteRequest(
            "write-normal", "password", "none", paths.first(), target.path, emptyList(), "", "standard", false,
            inputFiles = paths, onlyFolders = listOf(payload.path),
        ), password).getOrThrow()
        assertTrue(password.all { it == '\u0000' })
        assertEquals("", start.code)
        val operation = requireNotNull(start.operation)
        val observer = Pcv3AndroidResourceObservationReader(context)
        try {
            val terminal = withTimeout(180_000) {
                while (true) {
                    operation.resourceChallenge()?.let { challenge ->
                        assertTrue(challenge.submit(requireNotNull(observer.read())))
                    }
                    val snapshot = operation.snapshot()
                    if (snapshot.completionClass != "unknown") return@withTimeout snapshot
                    delay(20)
                }
                error("unreachable")
            }
            assertEquals("creation fixed KDF/admission: ${terminal.diagnostic}", "success", terminal.outcome)
            val output = requireNotNull(operation.output())
            ParcelFileDescriptor.open(saved, ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_READ_WRITE).use {
                val result = output.save(it)
                assertEquals("saved", result.code)
                assertFalse(result.cleanupIncomplete)
            }
            assertFalse(target.exists())
            assertEquals("", operation.release())
        } finally {
            if (operation.snapshot().completionClass != "unknown") {
                operation.output()?.discard()
                operation.release()
            }
        }
    }

    private fun providerCall(method: String, extras: Bundle? = null): Bundle {
        if (method == "reset") BoundedSafDocumentsProvider.grantAccessForTest(context)
        return requireNotNull(context.contentResolver.call(BoundedSafDocumentsProvider.AUTHORITY, "bounded-test-$method", null, extras))
    }

    private fun digest(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered().use { input ->
            val buffer = ByteArray(65_536)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun recordMemory(label: String, phase: String, entries: Int = 0, elapsedMillis: Long = 0) {
        val memory = Debug.MemoryInfo()
        Debug.getMemoryInfo(memory)
        val runtime = Runtime.getRuntime()
        val observation = JSONObject().put("test_only", true).put("lane", label).put("phase", phase)
            .put("entries", entries).put("elapsedMillis", elapsedMillis)
            .put("totalPssKiB", memory.totalPss).put("nativePssKiB", memory.nativePss)
            .put("dalvikPssKiB", memory.dalvikPss).put("artUsedBytes", runtime.totalMemory() - runtime.freeMemory())
            .put("artCommittedBytes", runtime.totalMemory()).put("nativeMallocBytes", Debug.getNativeHeapAllocatedSize())
        InstrumentationRegistry.getInstrumentation().sendStatus(2, Bundle().apply { putString("bounded_saf_memory", observation.toString()) })
    }
}
