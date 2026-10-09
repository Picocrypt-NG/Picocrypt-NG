package io.github.picocrypt_ng.picocrypt_ng

import android.Manifest
import android.app.Application
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleRegistry
import androidx.lifecycle.SAVED_STATE_REGISTRY_OWNER_KEY
import androidx.lifecycle.SavedStateViewModelFactory
import androidx.lifecycle.VIEW_MODEL_STORE_OWNER_KEY
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner
import androidx.lifecycle.enableSavedStateHandles
import androidx.lifecycle.viewmodel.MutableCreationExtras
import androidx.savedstate.SavedStateRegistry
import androidx.savedstate.SavedStateRegistryController
import androidx.savedstate.SavedStateRegistryOwner
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivityStateTest {
    @Test
    fun exportedActivityDoesNotRestoreSelectionFromLaunchIntentExtras() {
        val application = ApplicationProvider.getApplicationContext<Application>()
        if (Build.VERSION.SDK_INT >= 33) {
            InstrumentationRegistry.getInstrumentation().uiAutomation.grantRuntimePermission(
                application.packageName, Manifest.permission.POST_NOTIFICATIONS)
        }
        val foreign = File(application.filesDir, "intent-private-data-${System.nanoTime()}.pcv")
        foreign.writeText("unrelated app-private bytes")
        // Let the actual process-start cleanup finish before placing a selection.
        // A forged Intent must remain powerless even when it guesses a valid slot.
        ActivityScenario.launch(MainActivity::class.java).use { }
        val owned = File(application.filesDir, "picocrypt_files/input_file.pcv")
        assertTrue("Test must own an unused input slot", owned.createNewFile())
        owned.writeText("owned copied ciphertext")
        try {
            val intent = Intent(application, MainActivity::class.java)
                .putExtra("selected_filename", "forged.pcv")
                .putExtra("copied_file_path", owned.path)
                .putExtra("comments", "forged comments")
            ActivityScenario.launch<MainActivity>(intent).use { scenario ->
                scenario.onActivity { activity ->
                    val form = ViewModelProvider(activity)[MainViewModel::class.java].formState.value
                    assertEquals("", form.selectedFilename)
                    assertEquals("", form.copiedFilePath)
                    assertEquals("", form.comments)
                }
            }
            assertEquals("unrelated app-private bytes", foreign.readText())
            assertEquals("owned copied ciphertext", owned.readText())
        } finally { foreign.delete(); owned.delete() }
    }

    @Test
    fun registryRestoresLegitimateOwnedSelectionIntoANewViewModelWithoutCredentials() {
        val application = ApplicationProvider.getApplicationContext<Application>()
        val source = File(application.filesDir, "picocrypt_files/input_file.pcv")
        source.parentFile!!.mkdirs()
        assertTrue("Test must own an unused input slot", source.createNewFile())
        source.writeText("owned copied ciphertext")
        try {
            InstrumentationRegistry.getInstrumentation().runOnMainSync {
                val first = RegistryOwner(application, null)
                val before = first.viewModel()
                before.updateFormData(before.formState.value.copy(
                    selectedFilename = "original.pcv", copiedFilePath = source.path, comments = "saved comment"))
                before.updatePasswords("must not restore".toCharArray())
                val saved = Bundle()
                first.controller.performSave(saved)
                first.viewModelStore.clear()

                val second = RegistryOwner(application, saved)
                val after = second.viewModel()
                assertNotSame(before, after)
                assertEquals(source.path, after.formState.value.copiedFilePath)
                assertEquals("original.pcv", after.formState.value.selectedFilename)
                assertEquals("saved comment", after.formState.value.comments)
                assertTrue(after.formState.value.passwordInput.isEmpty())
                assertTrue(after.formState.value.confirmPasswordInput.isEmpty())
                second.viewModelStore.clear()
            }
        } finally { source.delete() }
    }

    private class RegistryOwner(private val application: Application, saved: Bundle?) :
        SavedStateRegistryOwner, ViewModelStoreOwner {
        override val lifecycle = LifecycleRegistry(this)
        override val viewModelStore = ViewModelStore()
        val controller = SavedStateRegistryController.create(this)
        override val savedStateRegistry: SavedStateRegistry get() = controller.savedStateRegistry

        init {
            controller.performAttach()
            enableSavedStateHandles()
            controller.performRestore(saved)
            lifecycle.currentState = Lifecycle.State.CREATED
        }

        fun viewModel(): MainViewModel {
            val extras = MutableCreationExtras().apply {
                this[ViewModelProvider.AndroidViewModelFactory.APPLICATION_KEY] = application
                this[SAVED_STATE_REGISTRY_OWNER_KEY] = this@RegistryOwner
                this[VIEW_MODEL_STORE_OWNER_KEY] = this@RegistryOwner
            }
            return ViewModelProvider(viewModelStore, SavedStateViewModelFactory(application, this), extras)[MainViewModel::class.java]
        }
    }
}
