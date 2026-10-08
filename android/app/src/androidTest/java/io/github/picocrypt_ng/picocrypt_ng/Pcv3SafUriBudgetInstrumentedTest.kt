package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/** Real Android Uri/Parcel sizing, with provider effects replaced at the platform boundary. */
@RunWith(AndroidJUnit4::class)
class Pcv3SafUriBudgetInstrumentedTest {
    @Test
    fun manyTinySegmentsAreRefusedBeforeFrameworkIdentityParsingOrProviderEffects() {
        val platform = RecordingPlatform()
        val session = DirectorySession()
        val manifest = requireNotNull(capturePcv3SafManifest(session, 8L * 1024 * 1024 + 300_000))
        // The actual document ID remains tiny. Cache cost is in 20,000 extra
        // path segments, each requiring a separate string and list slot.
        val tree = Uri.parse("content://provider/tree/root/document/root/" + "s/".repeat(20_000))
        val result = Pcv3SafArchiveProvider(platform).publish(tree, manifest, session, platform.newCancellation())
        assertEquals(Pcv3SafPublicationResult.NEEDS_ABORT, result)
        assertEquals(0, platform.normalizations)
        assertEquals(0, platform.identities)
        assertEquals(0, platform.creations)
        assertEquals(0, session.attempts)
    }

    @Test
    fun ordinaryFrameworkUrisRemainWithinTheAllowanceAndPublishOnce() {
        val platform = RecordingPlatform()
        val session = DirectorySession()
        val manifest = requireNotNull(capturePcv3SafManifest(session, 8L * 1024 * 1024 + 300_000))
        val result = Pcv3SafArchiveProvider(platform).publish(
            Uri.parse("content://provider/tree/root"), manifest, session, platform.newCancellation(),
        )
        assertEquals(Pcv3SafPublicationResult.READY_TO_FINISH, result)
        assertEquals(1, platform.creations)
        assertEquals(1, session.attempts)
        assertEquals(1, session.acknowledgements)
    }

    private class RecordingPlatform : Pcv3SafPlatform {
        private val android = AndroidPcv3SafPlatform(ApplicationProvider.getApplicationContext<Context>().contentResolver)
        var normalizations = 0
        var identities = 0
        var creations = 0
        override fun newCancellation() = android.newCancellation()
        override fun retainedUriWorkingBytes(document: Uri) = android.retainedUriWorkingBytes(document)
        override fun normalizeTreeRoot(tree: Uri): Uri? {
            normalizations++
            return android.normalizeTreeRoot(tree)
        }
        override fun documentIdentity(document: Uri): Pcv3SafDocumentIdentity? {
            identities++
            return android.documentIdentity(document)
        }
        override fun createDocument(parent: Uri, mimeType: String, displayName: String): Uri {
            creations++
            return Uri.parse("content://provider/document/created")
        }
        override fun queryDocument(document: Uri, cancellation: Pcv3SafCancellation) =
            Pcv3SafDocumentMetadata("provider", "created", "created", "folder", PCV3_SAF_DIRECTORY_MIME)
        override fun openDocument(document: Uri, mode: String, cancellation: Pcv3SafCancellation): Pcv3SafOriginalDescriptor? =
            error("directory publication must not open a file descriptor")
    }

    private class DirectorySession : Pcv3ArchiveSessionCapability, Pcv3SafEntrySession {
        var attempts = 0
        var acknowledgements = 0
        override fun hostMemoryBudgetBytes() = PCV3_SAF_MAX_WORKING_BYTES
        override fun entryCount() = 1L
        override fun entry(index: Long) = Pcv3ArchiveEntryData("folder", -1, true, 0).takeIf { index == 0L }
        override fun attempt(index: Long): Pcv3ArchiveStepData {
            attempts++
            return Pcv3ArchiveStepData("attempted", index)
        }
        override fun ackDirectory(index: Long): Pcv3ArchiveStepData {
            acknowledgements++
            return Pcv3ArchiveStepData("ready", index + 1)
        }
        override fun confirmCrashReceiptPersisted(receipt: String) = error("provider cannot confirm receipts")
        override fun writeFd(index: Long, descriptor: Long) = error("directory cannot write")
        override fun cancel() = error("provider cannot cancel a session")
        override fun finish(): Pcv3SnapshotData = error("provider cannot finish a session")
        override fun abort(): Pcv3SnapshotData = error("provider cannot abort a session")
    }
}
