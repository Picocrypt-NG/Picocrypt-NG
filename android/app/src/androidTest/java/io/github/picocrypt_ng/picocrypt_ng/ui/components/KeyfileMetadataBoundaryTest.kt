package io.github.picocrypt_ng.picocrypt_ng.ui.components

import android.app.Application
import android.content.Context
import android.content.ContextWrapper
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.core.app.ActivityOptionsCompat
import androidx.lifecycle.SavedStateHandle
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.CopyBoundaryProvider
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.R
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class KeyfileMetadataBoundaryTest {
    @get:Rule val compose = createComposeRule()
    private val application: Application get() = ApplicationProvider.getApplicationContext()
    private val handler = Handler(Looper.getMainLooper())

    @Test
    fun selectedProviderQueryLeavesMainResponsiveAndDisposalCancelsQuery() {
        provider("reset", Bundle().apply { putString("metadata", "block") })
        val root = File(application.filesDir, "keyfile-metadata-blocked").apply { mkdirs() }
        val isolated = object : ContextWrapper(application) { override fun getFilesDir(): File = root }
        val viewModel = MainViewModel(application, SavedStateHandle())
        val registry = PickerRegistry()
        val visible = mutableStateOf(true)
        compose.setContent {
            CompositionLocalProvider(LocalContext provides isolated, LocalActivityResultRegistryOwner provides registry) {
                if (visible.value) AddKeyfile(viewModel)
            }
        }
        try {
            compose.onNodeWithText(application.getString(R.string.add)).performClick()
            handler.post { registry.deliver() }
            awaitState("queryBlocked")
            val sentinel = CountDownLatch(1)
            handler.post { sentinel.countDown() }
            assertTrue("Blocked provider metadata must not hold the main thread", sentinel.await(500, TimeUnit.MILLISECONDS))
            handler.post { visible.value = false }
            awaitState("queryCancelled")
            assertTrue("Cancelled metadata must never add a keyfile", viewModel.formState.value.keyfileFilenames.isEmpty())
            assertTrue(File(root, "picocrypt_files").list().isNullOrEmpty())
        } finally {
            provider("release-query")
            compose.waitForIdle()
            root.deleteRecursively()
            provider("cleanup")
        }
    }

    @Test
    fun malformedMetadataUsesFixedFallbackAndFiniteProviderStillCopies() {
        val root = File(application.filesDir, "keyfile-metadata-fallback").apply { mkdirs() }
        val isolated = object : ContextWrapper(application) { override fun getFilesDir(): File = root }
        val viewModel = MainViewModel(application, SavedStateHandle())
        val registry = PickerRegistry()
        compose.setContent {
            CompositionLocalProvider(LocalContext provides isolated, LocalActivityResultRegistryOwner provides registry) {
                AddKeyfile(viewModel)
            }
        }
        try {
            for ((index, mode) in listOf("no-cursor", "empty", "null", "oversized", "duplicate", "throw", "normal").withIndex()) {
                provider("reset", Bundle().apply { putString("metadata", mode) })
                compose.onNodeWithText(application.getString(R.string.add)).performClick()
                handler.post { registry.deliver() }
                compose.waitUntil(5000) { viewModel.formState.value.keyfileFilenames.size == index + 1 }
                val keyfile = viewModel.formState.value.keyfileFilenames.last()
                assertEquals(if (mode == "normal") "provider-key" else "keyfile_$index", keyfile.displayName)
                assertArrayEquals(CopyBoundaryProvider.body(), File(keyfile.internalPath).readBytes())
                val state = provider("state")
                assertTrue("Only display metadata belongs in this query", state.getBoolean("displayNameOnly"))
                assertTrue("Provider query must receive lifecycle cancellation", state.getBoolean("queryCancellable"))
                if (mode != "no-cursor" && mode != "throw") {
                    compose.waitUntil(3000) { provider("state").getInt("cursorCloses") > 0 }
                }
            }
        } finally { compose.waitForIdle(); root.deleteRecursively(); provider("cleanup") }
    }

    private class PickerRegistry : ActivityResultRegistry(), ActivityResultRegistryOwner {
        override val activityResultRegistry: ActivityResultRegistry get() = this
        private var request = -1
        override fun <I, O> onLaunch(requestCode: Int, contract: ActivityResultContract<I, O>, input: I, options: ActivityOptionsCompat?) {
            request = requestCode
        }
        fun deliver() { check(dispatchResult(request, CopyBoundaryProvider.URI)) }
    }

    private fun awaitState(key: String) {
        compose.waitUntil(5000) { provider("state").getBoolean(key) }
        assertTrue("Provider state $key was not reached", provider("state").getBoolean(key))
    }

    private fun provider(method: String, extras: Bundle? = null): Bundle =
        requireNotNull(application.contentResolver.call(CopyBoundaryProvider.URI, method, null, extras))
}
