package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.os.Process
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import android.system.StructStat
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest

/** Opt-in host crash coordinator: killed hold is a prerequisite; only fresh recover may pass.
 * Protects native v2 journal discovery/retirement, including an empty stage, not plaintext erasure.
 */
@RunWith(AndroidJUnit4::class)
class Pcv3JournalRestartDeviceTest {
    @Test
    fun optInNativeV2JournalRestartRetiresOnlyTheOwnedStage() = runBlocking {
        val arguments = InstrumentationRegistry.getArguments()
        val phase = arguments.getString("pcv3JournalPhase")
        assumeTrue("opt-in native restart gate requires the host crash coordinator and hold/recover phase", phase != null)
        assertTrue("unknown restart phase: $phase", phase == "hold" || phase == "recover")
        val runId = arguments.getString("pcv3JournalRunId") ?: throw AssertionError("restart gate requires a run ID")
        assertTrue("invalid restart run ID", runId.matches(Regex("[A-Za-z0-9_-]{1,64}")))
        val context = ApplicationProvider.getApplicationContext<Context>()
        val parent = FileCopyService.ensurePcv3PrivateParent(context)
            ?: throw AssertionError("real app-private parent was refused")
        val fixture = File(context.filesDir, "pcv3-journal-restart-$runId")
        val source = File(fixture, "source.bin")
        val sentinel = File(parent, "journal-restart-sentinel-$runId.bin")
        val marker = File(fixture, "ready.json")
        val target = File(FileCopyService.getPcv3RetainedOutputPath(context))
        val receipt = Pcv3ReceiptStore.receiptFile(context)
        assertFalse("this lane must start without receipt custody", receipt.exists())
        assertFalse("restart must not rely on deleting a published output", target.exists())

        if (phase == "hold") {
            assertFalse("earlier restart fixture must remain visible", fixture.exists())
            assertFalse("earlier sentinel must not be overwritten", sentinel.exists())
            assertTrue("fresh lane must have no private-operation residue", privateDirectories(parent).isEmpty())
            assertTrue(StartupCleanup.runBeforeUi(context))
            assertTrue(StartupCleanup.allowsPcv3Dispatch())
            assertTrue(fixture.mkdir())
            source.writeBytes(SOURCE_BYTES)
            sentinel.writeBytes(SENTINEL_BYTES)
            val lifecycle = Pcv3Lifecycle(GoBridge.pcv3Bridge)
            val password = "public restart test password".toCharArray()
            try {
                lifecycle.start(
                    Pcv3WriteRequest("write-normal", "password", "none", source.path, target.path,
                        emptyList(), "", "standard", false),
                    password, receipt,
                ).getOrThrow()
                assertTrue("lifecycle must clear caller credentials", password.all { it == '\u0000' })
                assertTrue(lifecycle.installResourceObservationReader(Pcv3AndroidResourceObservationReader(context)))
                val deadline = SystemClock.elapsedRealtime() + 120_000
                while (SystemClock.elapsedRealtime() < deadline) {
                    val live = lifecycle.refreshPcv3().getOrThrow() as? Pcv3Presentation.Live
                        ?: throw AssertionError("native operation stopped before the host killed it")
                    assertEquals("host must kill live custody", "unknown", live.snapshot.completionClass)
                    assertEquals("unknown-outcome", live.snapshot.semantic.outcome)
                    assertFalse(live.snapshot.publication.attempted)
                    assertFalse(target.exists())
                    assertFalse(receipt.exists())
                    // Both statuses occur after PersistCleanupJournal returned, including directory sync.
                    if (!marker.exists() && live.snapshot.statusCode in listOf("checking-resources", "deriving-key")) {
                        val directory = privateDirectories(parent).singleOrNull()
                            ?: throw AssertionError("live native write must own exactly one private directory")
                        val state = journalState(parent, directory.name, target.name)
                            .put("runId", runId).put("pid", Process.myPid())
                            .put("status", live.snapshot.statusCode)
                        FileOutputStream(marker).use { output ->
                            output.write(state.toString().toByteArray(Charsets.UTF_8))
                            output.fd.sync()
                        }
                    }
                    delay(10)
                }
                throw AssertionError("host did not kill the live journal owner within the bounded hold")
            } finally {
                lifecycle.cancelCurrentPcv3ForHost()
                lifecycle.refreshPcv3().getOrNull()?.let { presentation ->
                    if (presentation is Pcv3Presentation.Live && presentation.outputPending) {
                        lifecycle.discardPcv3Output(presentation.operationId, presentation.generation).getOrThrow()
                    }
                }
            }
        } else {
            assertFalse("recover must use a fresh process, never a reset test singleton", StartupCleanup.allowsPcv3Dispatch())
            assertTrue("host-killed hold marker is required", marker.isFile)
            assertTrue(marker.length() in 1L..2_048L)
            val recorded = JSONObject(marker.readText(Charsets.UTF_8))
            assertEquals(runId, recorded.getString("runId"))
            assertTrue("recover must not reuse the hold process", Process.myPid() != recorded.getInt("pid"))
            val current = journalState(parent, recorded.getString("directory"), target.name)
            for (key in IDENTITY_FIELDS) {
                assertEquals("post-death native custody changed: $key", recorded.get(key).toString(), current.get(key).toString())
            }
            assertArrayEquals(SOURCE_BYTES, source.readBytes())
            assertArrayEquals(SENTINEL_BYTES, sentinel.readBytes())
            assertTrue("all-default production startup cleanup must recover v2 custody", StartupCleanup.runBeforeUi(context))
            assertTrue("dispatch must wait for completed native startup cleanup", StartupCleanup.allowsPcv3Dispatch())
            val directory = File(parent, recorded.getString("directory"))
            assertFalse(File(directory, recorded.getString("stage")).exists())
            assertFalse(File(directory, JOURNAL_NAME).exists())
            assertFalse("empty owned operation directory must also retire", directory.exists())
            assertTrue(privateDirectories(parent).isEmpty())
            assertFalse(target.exists())
            assertFalse(receipt.exists())
            assertArrayEquals("original source must survive startup", SOURCE_BYTES, source.readBytes())
            assertArrayEquals("unrelated parent entry must survive startup", SENTINEL_BYTES, sentinel.readBytes())
            assertTrue(source.delete())
            assertTrue(sentinel.delete())
            assertTrue(marker.delete())
            assertTrue(fixture.delete())
        }
    }

    private fun privateDirectories(parent: File): List<File> =
        (parent.listFiles() ?: throw AssertionError("private parent cannot be listed"))
            .filter { it.name.startsWith(".picocrypt-pcv3-private-") }

    /** Inspect the real native record and kernel identities; never construct or rewrite a journal. */
    private fun journalState(parent: File, directoryName: String, targetName: String): JSONObject {
        assertEquals(directoryName, File(directoryName).name)
        assertTrue(directoryName.startsWith(".picocrypt-pcv3-private-"))
        val directory = File(parent, directoryName)
        val directoryStat = Os.lstat(directory.path)
        assertTrue(OsConstants.S_ISDIR(directoryStat.st_mode))
        assertEquals(Process.myUid(), directoryStat.st_uid)
        assertEquals(0x1c0, directoryStat.st_mode and 0x1ff)
        val journal = File(directory, JOURNAL_NAME)
        val journalStat = Os.lstat(journal.path)
        assertTrue(OsConstants.S_ISREG(journalStat.st_mode))
        assertEquals(1L, journalStat.st_nlink)
        assertTrue(journalStat.st_size in 1L..2_048L)
        val bytes = journal.readBytes()
        val record = JSONObject(bytes.toString(Charsets.UTF_8))
        assertEquals("only the changed real native v2 contract closes this gate", 2, record.getInt("version"))
        assertEquals(targetName, record.getString("target"))
        assertIdentity(record.getJSONObject("parent"), directoryStat)
        assertIdentity(record.getJSONObject("destination"), Os.lstat(parent.path))
        val stageName = record.getString("stage")
        assertEquals(stageName, File(stageName).name)
        assertTrue(stageName.startsWith(".picocrypt-pcv3-"))
        val stageStat = Os.lstat(File(directory, stageName).path)
        assertTrue(OsConstants.S_ISREG(stageStat.st_mode))
        assertIdentity(record.getJSONObject("file"), stageStat)
        assertEquals(1L, stageStat.st_nlink)
        assertEquals(stageStat.st_nlink, record.getJSONObject("file").getLong("links"))
        return JSONObject().put("directory", directoryName).put("stage", stageName)
            .put("directoryDevice", directoryStat.st_dev).put("directoryInode", directoryStat.st_ino)
            .put("journalDevice", journalStat.st_dev).put("journalInode", journalStat.st_ino)
            .put("stageDevice", stageStat.st_dev).put("stageInode", stageStat.st_ino)
            .put("journalSha256", MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') })
    }

    private fun assertIdentity(record: JSONObject, stat: StructStat) {
        assertEquals(record.getLong("device"), stat.st_dev)
        assertEquals(record.getLong("inode"), stat.st_ino)
        assertEquals(record.getLong("uid"), stat.st_uid.toLong())
        assertEquals(record.getLong("gid"), stat.st_gid.toLong())
        // Go's FileMode directory bit differs from the POSIX S_IFDIR bit; permissions agree.
        assertEquals(record.getLong("mode") and 0x1ff, (stat.st_mode and 0x1ff).toLong())
    }

    companion object {
        private const val JOURNAL_NAME = ".picocrypt-pcv3-stage.journal"
        private val SOURCE_BYTES = "public native restart source\n".toByteArray(Charsets.UTF_8)
        private val SENTINEL_BYTES = "unrelated parent entry must remain byte-exact\n".toByteArray(Charsets.UTF_8)
        private val IDENTITY_FIELDS = listOf("directory", "stage", "directoryDevice", "directoryInode",
            "journalDevice", "journalInode", "stageDevice", "stageInode", "journalSha256")
    }
}
