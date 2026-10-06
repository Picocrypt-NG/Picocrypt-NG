package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Parcel
import android.os.Process
import android.provider.DocumentsContract
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Source staging through Android's real URI encoder, Binder cursor and descriptors. */
@RunWith(AndroidJUnit4::class)
class StagingSourceDeviceTest {
    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Test
    fun longPercentEncodedDocumentIdsCopyExactBytesWithinConstructionAllowance() = runBlocking {
        provider("reset")
        try {
            provider("seed-source", Bundle().apply { putBoolean("encodedIds", true) })
            assertSourceGrant()
            val selected = StagingService.copyTreeToStaging(context, BoundedSafDocumentsProvider.tree).getOrThrow()
            assertEquals(2, selected.inputFiles.size)
            assertEquals("a", File(selected.stagingRoot, "bounded-saf-provider/a.txt").readText())
            assertEquals("b", File(selected.stagingRoot, "bounded-saf-provider/sub/b.txt").readText())
            assertEquals(2, provider("source-state").getInt("opens"))
            recordUriCalibration()
            assertTrue(StagingService.wipeStaging(context))
            assertSourceBody("root/a.txt", "a")
            assertSourceBody("root/sub/b.txt", "b")
        } finally {
            assertTrue(StagingService.wipeStaging(context))
            assertTrue(provider("cleanup").getBoolean("cleaned"))
        }
    }

    @Test
    fun aggregateEncodedSourceIdentitiesRefuseBeforeCopyAndPreservePreviousOwner() = runBlocking {
        assertTrue(StagingService.wipeStaging(context))
        val old = File(context.filesDir, "picocrypt_files/staging/previous-private-file")
        assertTrue(old.parentFile!!.mkdirs())
        old.writeText("previous owner must survive admission refusal")
        provider("reset")
        try {
            provider("seed-source", Bundle().apply { putBoolean("encodedIds", true); putInt("count", 300) })
            assertSourceGrant()
            val result = StagingService.copyTreeToStaging(context, BoundedSafDocumentsProvider.tree)
            assertTrue("real framework URI plan must exhaust its bounded allowance", result.isFailure)
            assertEquals("PCV3_RESOURCE_LIMIT", (result.exceptionOrNull() as? Pcv3BridgeFailure)?.code)
            assertEquals(0, provider("source-state").getInt("opens"))
            assertEquals("previous owner must survive admission refusal", old.readText())
            assertFalse(File(old.parentFile, "bounded-saf-provider").exists())
            assertSourceBody("root/source-0.txt", "source 0")
            assertSourceBody("root/source-299.txt", "source 299")
            recordUriCalibration()
        } finally {
            assertTrue(StagingService.wipeStaging(context))
            assertTrue(provider("cleanup").getBoolean("cleaned"))
        }
    }

    private fun assertSourceGrant() {
        val tree = BoundedSafDocumentsProvider.tree
        assertEquals("test source must have an actual Android URI grant", PackageManager.PERMISSION_GRANTED,
            context.checkUriPermission(tree, Process.myPid(), Process.myUid(), Intent.FLAG_GRANT_READ_URI_PERMISSION))
        context.contentResolver.query(DocumentsContract.buildDocumentUriUsingTree(tree, "root"),
            arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME), null, null, null).use {
            assertTrue("granted root metadata must be readable", requireNotNull(it).moveToFirst())
            assertEquals("bounded-saf-provider", it.getString(0))
        }
    }

    private fun assertSourceBody(id: String, expected: String) {
        val uri = DocumentsContract.buildDocumentUriUsingTree(BoundedSafDocumentsProvider.tree, " /%Ж😀x".repeat(4_000) + id)
        assertEquals(expected, requireNotNull(context.contentResolver.openInputStream(uri)).bufferedReader().use { it.readText() })
    }

    private fun recordUriCalibration() {
        val source = AndroidStagingSource(context)
        val tree = BoundedSafDocumentsProvider.tree
        val document = source.documentUri(tree, " /%Ж😀x".repeat(4_000) + "root/source-299.txt")
        val parcel = Parcel.obtain()
        try {
            document.writeToParcel(parcel, 0)
            InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
                putString("sourceUriCalibration", "idUtf8Bytes=40018 parcelBytes=${parcel.dataSize()} " +
                    "encodedPathChars=${document.encodedPath!!.length} retainedWorkingBytes=${source.uriWorkingBytes(document)}")
            })
        } finally { parcel.recycle() }
    }

    private fun provider(method: String, extras: Bundle? = null): Bundle {
        if (method == "reset") BoundedSafDocumentsProvider.grantAccessForTest(context)
        return requireNotNull(context.contentResolver.call(BoundedSafDocumentsProvider.AUTHORITY, "bounded-test-$method", null, extras))
    }
}
