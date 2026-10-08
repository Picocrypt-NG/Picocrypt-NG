package io.github.picocrypt_ng.picocrypt_ng

import android.app.Application
import android.content.Context
import androidx.lifecycle.SavedStateHandle
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsFocused
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.width
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.picocrypt_ng.picocrypt_ng.ui.components.PCV3_CONSENT_TAG
import io.github.picocrypt_ng.picocrypt_ng.ui.components.PCV3_PROGRESS_TAG
import io.github.picocrypt_ng.picocrypt_ng.ui.components.PCV3_RESULT_TAG
import io.github.picocrypt_ng.picocrypt_ng.ui.components.DecryptOptionsCard
import io.github.picocrypt_ng.picocrypt_ng.ui.components.ErrorDialog
import io.github.picocrypt_ng.picocrypt_ng.ui.components.ProgressCard
import io.github.picocrypt_ng.picocrypt_ng.ui.components.WorkButton
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Product-Compose assertions for the live PCV3 snapshot and capability contract. */
@RunWith(AndroidJUnit4::class)
class Pcv3UiContractTest {
    @get:Rule
    val compose = createComposeRule()

    @After
    fun restoreTouchMode() {
        InstrumentationRegistry.getInstrumentation().setInTouchMode(true)
    }

    /**
     * Focus navigation does not exist in touch mode — the default state of
     * every phone and emulator until a key is pressed — and a dialog cannot
     * grant focus there. The safe-default focus contract protects keyboard
     * and DPAD users, so it is exercised in that environment; [restoreTouchMode]
     * returns the device to its natural state afterwards.
     */
    private fun leaveTouchMode() {
        InstrumentationRegistry.getInstrumentation().setInTouchMode(false)
    }

    /**
     * Leaving touch mode reaches the dialog through several window-manager
     * hops, so the safe-default focus grant lands after the next idle sync;
     * wait for the grant instead of racing it, then keep the exact assertion.
     */
    private fun assertEventuallyFocused(content: String) {
        compose.waitUntil(FOCUS_TIMEOUT_MILLIS) {
            compose.onNodeWithText(content)
                .fetchSemanticsNode()
                .config
                .getOrElse(SemanticsProperties.Focused) { false }
        }
        compose.onNodeWithText(content).assertIsFocused()
    }

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    @Test
    fun retainedPlaintextShowsSaveFailureAndExplicitConfirmedDiscard() = retainedOutputDiscard(false)

    @Test
    fun retainedCiphertextShowsSaveFailureAndExplicitConfirmedDiscard() = retainedOutputDiscard(true)

    private fun retainedOutputDiscard(creation: Boolean) {
        val initial = live(snapshot = cleanSnapshot(), output = UiOutput(), outputPending = true)
            .copy(isCreation = creation)
        val state = mutableStateOf<Pcv3Presentation?>(initial)
        val saveError = mutableStateOf<AppError?>(AppError.FileError.SaveFailed(
            messageResId = R.string.pcv3_output_provider_unsupported,
        ))
        val mainViewModel = newMainViewModel()
        val operationViewModel = OperationViewModel()
        var discardCalls = 0
        compose.setContent {
            ProgressCard(
                mainViewModel = mainViewModel,
                operationViewModel = operationViewModel,
                pcv3Presentation = state.value,
                onBeginPcv3Save = { _, _ -> "output" },
                onCompletePcv3Save = { _, _ -> },
                onDiscardPcv3Output = { operationId, generation ->
                    assertCurrent(state.value, operationId, generation)
                    discardCalls += 1
                    state.value = Pcv3Presentation.Final(
                        snapshot = initial.snapshot, operationId = operationId, generation = generation,
                        outputAction = Pcv3OutputResultView("discarded", false), isCreation = creation,
                    )
                },
                onClosePcv3Result = { _, _ -> state.value = null },
            )
            ErrorDialog(
                error = pcv3VisibleError(saveError.value, state.value),
                onDismiss = { saveError.value = null },
            )
        }
        compose.onNodeWithText(text(R.string.pcv3_output_provider_unsupported)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.ok)).performClick()
        compose.onNodeWithText(text(if (creation) R.string.pcv3_save_created_volume else R.string.pcv3_save_decrypted_output)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.discard_output)).performClick()
        compose.onNodeWithText(text(R.string.pcv3_discard_retained_body)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.cancel)).performClick()
        assertEquals(0, discardCalls)
        compose.onNodeWithText(text(R.string.discard_output)).performClick()
        compose.onNodeWithText(text(R.string.discard_output)).performClick()
        assertEquals(1, discardCalls)
        compose.onNodeWithText(text(R.string.pcv3_retained_discarded_body)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.pcv3_output_discarded_close)).performClick()
        assertNull(state.value)
    }

    @Test
    fun c11ConsentEmpty() {
        val consent = UiConsent("force-unverified-normal", listOf("primary", "backup"))
        val presentation = live(consent = consent)
        val mainViewModel = newMainViewModel()

        compose.setContent {
            DecryptOptionsCard(
                viewModel = mainViewModel,
                pcv3Presentation = presentation,
                onSelectPcv3ConsentRole = { _, _, _ -> error("no role should be chosen") },
                onConfirmPcv3Consent = { _, _ -> error("disabled confirmation invoked") },
                onRefusePcv3Consent = { _, _ -> },
            )
        }

        compose.onNodeWithTag(PCV3_CONSENT_TAG).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.pcv3_consent_confirm)).assertIsNotEnabled()
        leaveTouchMode()
        assertEventuallyFocused(text(R.string.pcv3_consent_cancel))
        assertNull(presentation.consent?.selectedRole)
        assertTrue(consent.live)
    }

    @Test
    fun c12ConsentDisappears() {
        val consent = UiConsent("force-unverified-normal", listOf("primary", "backup"))
        val state = mutableStateOf<Pcv3Presentation?>(live(consent = consent))
        val mainViewModel = newMainViewModel()
        compose.setContent {
            DecryptOptionsCard(
                viewModel = mainViewModel,
                pcv3Presentation = state.value,
                onSelectPcv3ConsentRole = { _, _, _ -> },
                onConfirmPcv3Consent = { _, _ -> error("confirmation must not run") },
                onRefusePcv3Consent = { operationId, generation ->
                    assertCurrent(state.value, operationId, generation)
                    assertEquals("", consent.refuse())
                    state.value = final(refusedSnapshot(), operationId, generation)
                },
            )
        }

        compose.onNodeWithText(text(R.string.pcv3_consent_cancel)).performClick()

        compose.onNodeWithTag(PCV3_CONSENT_TAG).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.pcv3_consent_confirm)).assertDoesNotExist()
        assertEquals(1, consent.refuseCalls)
        assertFalse(consent.live)
        assertEquals("refused", state.value?.snapshot?.completionClass)
    }

    @Test
    fun c13PartialConsent() {
        val firstConsent = UiConsent("force-unverified-normal", listOf("primary", "backup"))
        val state = mutableStateOf<Pcv3Presentation?>(live(consent = firstConsent))
        val mainViewModel = newMainViewModel()
        compose.setContent {
            DecryptOptionsCard(
                viewModel = mainViewModel,
                pcv3Presentation = state.value,
                onSelectPcv3ConsentRole = { operationId, generation, role ->
                    val current = state.value as Pcv3Presentation.Live
                    assertCurrent(current, operationId, generation)
                    state.value = current.copy(consent = current.consent?.copy(selectedRole = role))
                },
                onConfirmPcv3Consent = { _, _ -> error("partial consent must not confirm") },
                onRefusePcv3Consent = { _, _ -> },
            )
        }

        compose.onNodeWithText(text(R.string.pcv3_consent_acknowledgement)).performClick()
        compose.onNodeWithText(text(R.string.pcv3_consent_confirm)).assertIsNotEnabled()

        val secondConsent = UiConsent("force-unverified-normal", listOf("primary", "backup"))
        compose.runOnIdle { state.value = live(generation = 2, consent = secondConsent) }
        compose.onNodeWithText(text(R.string.pcv3_consent_role_primary)).performClick()
        compose.onNodeWithText(text(R.string.pcv3_consent_confirm)).assertIsNotEnabled()
        assertEquals("primary", (state.value as Pcv3Presentation.Live).consent?.selectedRole)
        assertTrue(secondConsent.live)
    }

    @Test
    fun c14UnknownProgress() {
        val hostile = workingSnapshot(statusCode = "PRIVATE /data/user/0/plaintext")
        val mainViewModel = newMainViewModel()
        val operationViewModel = OperationViewModel()
        compose.setContent {
            ProgressCard(
                mainViewModel = mainViewModel,
                operationViewModel = operationViewModel,
                pcv3Presentation = live(snapshot = hostile),
                pcv3Intent = intent(Pcv3ActionIntent.DECRYPT),
                onCancelPcv3 = { _, _ -> },
                onClosePcv3Result = { _, _ -> error("unknown progress is not a result") },
                onClosePcv3Archive = { _, _ -> error("unknown progress has no archive action") },
            )
        }

        compose.onNodeWithTag(PCV3_PROGRESS_TAG).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.pcv3_progress_working)).assertIsDisplayed()
        compose.onNodeWithText("PRIVATE /data/user/0/plaintext").assertDoesNotExist()
        compose.onNode(indeterminateProgress()).assertExists()
        compose.onNodeWithText(text(R.string.pcv3_archive_close)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.pcv3_publication_close)).assertDoesNotExist()
    }

    @Test
    fun c15Inflight() {
        val operation = UiOperation("operation-in-flight", workingSnapshot())
        val active = live(
            snapshot = workingSnapshot(Pcv3ProgressStatus.DERIVING_KEY),
            operation = operation,
        )
        val state = mutableStateOf<Pcv3Presentation?>(null)
        val source = File.createTempFile("pcv3-c15-", ".pcv", context.cacheDir)
        val mainViewModel = MainViewModel(
            ApplicationProvider.getApplicationContext<Application>(),
            SavedStateHandle(),
        )
        assertNull(mainViewModel.claimPcv3Normal("in-flight.pcv", source.absolutePath))
        mainViewModel.setPcv3Action(Pcv3ActionIntent.RECOVERY)
        mainViewModel.setPcv3FactorPolicy(Pcv3FactorPolicyIntent.PASSWORD_ONLY)
        mainViewModel.updatePasswords(password = "test credential".toCharArray())
        assertTrue(mainViewModel.formState.value.isFormValid)
        val operationViewModel = OperationViewModel()
        try {
            compose.setContent {
                WorkButton(
                    mainViewModel = mainViewModel,
                    operationViewModel = operationViewModel,
                    pcv3Presentation = state.value,
                )
                state.value?.let { presentation ->
                    ProgressCard(
                        mainViewModel = mainViewModel,
                        operationViewModel = operationViewModel,
                        pcv3Presentation = presentation,
                        pcv3Intent = intent(Pcv3ActionIntent.RECOVERY),
                        onCancelPcv3 = { operationId, generation ->
                            assertCurrent(state.value, operationId, generation)
                            state.value = final(
                                projectPcv3Snapshot(operation.cancel()),
                                operationId,
                                generation,
                            )
                        },
                        onClosePcv3Result = { _, _ -> },
                        onClosePcv3Archive = { _, _ -> },
                    )
                }
            }

            compose.onNodeWithText(text(R.string.pcv3_start_recovery)).assertIsDisplayed()
            compose.runOnIdle { state.value = active }
            compose.onNodeWithText(text(R.string.pcv3_progress_deriving_key)).assertIsDisplayed()
            compose.onNodeWithText(text(R.string.pcv3_start_decrypt)).assertDoesNotExist()
            compose.onNodeWithText(text(R.string.pcv3_start_recovery)).assertDoesNotExist()
            compose.onNodeWithText(text(R.string.pcv3_start_force_recovery)).assertDoesNotExist()
            compose.onNodeWithText(text(R.string.pcv3_cancel_decryption)).assertDoesNotExist()
            compose.onNodeWithText(text(R.string.pcv3_cancel_recovery)).performClick()

            compose.onNodeWithText(text(R.string.pcv3_cancel_recovery)).assertDoesNotExist()
            compose.onNodeWithText(text(R.string.pcv3_outcome_cancelled_title)).assertIsDisplayed()
            assertEquals(1, operation.cancelCalls)
            assertFalse(operation.live)
        } finally {
            mainViewModel.clearSensitiveData(clearFiles = true)
            source.delete()
        }
    }

    @Test
    fun c16ResourceRefusal() = resourceRefusal(
        resourceSnapshot("resource-insufficient"),
        R.string.pcv3_resource_insufficient_title, R.string.pcv3_resource_insufficient_body,
    )

    @Test
    fun workingMemoryBudgetRefusalHasLocalizedNoticeAndNoCredentialRetry() = resourceRefusal(
        resourceSnapshot("resource-limit").copy(
            semantic = Pcv3Semantic("operation-failed", "resource-budget", "PCV3_OPERATION_FAILED"),
            completionClass = "no-output",
        ),
        R.string.pcv3_resource_limit_title, R.string.pcv3_resource_limit_body,
    )

    private fun resourceRefusal(snapshot: Pcv3SnapshotView, title: Int, body: Int) {
        val state = mutableStateOf<Pcv3Presentation?>(
            final(snapshot),
        )
        val mainViewModel = newMainViewModel()
        val operationViewModel = OperationViewModel()
        compose.setContent {
            state.value?.let { presentation ->
                ProgressCard(
                    mainViewModel = mainViewModel,
                    operationViewModel = operationViewModel,
                    pcv3Presentation = presentation,
                    pcv3Intent = intent(Pcv3ActionIntent.DECRYPT),
                    onCancelPcv3 = { _, _ -> error("refusal cannot cancel") },
                    onClosePcv3Result = { operationId, generation ->
                        assertCurrent(state.value, operationId, generation)
                        state.value = null
                    },
                    onClosePcv3Archive = { _, _ -> error("refusal has no archive") },
                )
            }
        }

        compose.onNodeWithText(text(title)).assertIsDisplayed()
        compose.onNodeWithText(text(body)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.retry)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.force_decrypt)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.save)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.pcv3_resource_close)).performClick()
        compose.onNodeWithTag(PCV3_RESULT_TAG).assertDoesNotExist()
        assertNull(state.value)
    }

    @Test
    fun c17InvalidProgress() {
        val invalid = workingSnapshot(
            statusCode = Pcv3ProgressStatus.RECOVERING,
            statusArgs = listOf("18446744073709551615", "1"),
        )
        val mainViewModel = newMainViewModel()
        val operationViewModel = OperationViewModel()
        compose.setContent {
            ProgressCard(
                mainViewModel = mainViewModel,
                operationViewModel = operationViewModel,
                pcv3Presentation = live(snapshot = invalid),
                pcv3Intent = intent(Pcv3ActionIntent.RECOVERY),
                onCancelPcv3 = { _, _ -> },
                onClosePcv3Result = { _, _ -> },
                onClosePcv3Archive = { _, _ -> },
            )
        }

        compose.onNodeWithText(text(R.string.pcv3_progress_working)).assertIsDisplayed()
        compose.onNode(indeterminateProgress()).assertExists()
    }

    @Test
    fun uiD02AtomicRoleSet() {
        val invalid = UiConsent("force-unverified-normal", listOf("primary"))
        val projected = invalid.toViewOrNull()
        assertNull(projected)
        val presentation = live(consent = null, consentView = projected)
        val mainViewModel = newMainViewModel()

        compose.setContent {
            DecryptOptionsCard(
                viewModel = mainViewModel,
                pcv3Presentation = presentation,
                onSelectPcv3ConsentRole = { _, _, _ -> error("partial role set was actionable") },
                onConfirmPcv3Consent = { _, _ -> error("partial role set was confirmable") },
                onRefusePcv3Consent = { _, _ -> error("UI must not synthesize a partial dialog") },
            )
        }

        compose.onNodeWithTag(PCV3_CONSENT_TAG).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.pcv3_consent_role_primary)).assertDoesNotExist()
        assertTrue(invalid.live)
        assertEquals(0, invalid.chooseCalls)
        assertEquals(0, invalid.refuseCalls)
    }

    @Test
    fun b02SmallScreenLargeFont() {
        val consent = UiConsent("force-unverified-d1", listOf("d1-front", "d1-tail"))
        val archive = UiArchive(archiveClosedSnapshot())
        val output = UiOutput()
        val artifact = artifactMetadata()
        val firstArtifactPage = Pcv3ArtifactPageView(
            offsetDecimal = "0",
            ranges = (0 until 128).map { index ->
                Pcv3ArtifactRangeView(
                    recordIndex = index.toString(),
                    start = (index * 10).toString(),
                    end = (index * 10 + 9).toString(),
                    status = "verified",
                )
            },
        )
        val lastArtifactPage = Pcv3ArtifactPageView(
            offsetDecimal = "128",
            ranges = listOf(Pcv3ArtifactRangeView("128", "1280", "1289", "missing")),
        )
        val state = mutableStateOf<Pcv3Presentation?>(live(consent = consent))
        val artifactDetails = mutableStateOf<Pcv3ArtifactDetailsUiState>(
            Pcv3ArtifactDetailsUiState.Closed,
        )
        var discardCalls = 0
        var inspectionCalls = 0
        val loadedOffsets = mutableListOf<String>()
        val mainViewModel = newMainViewModel()
        val operationViewModel = OperationViewModel()
        compose.setContent {
            CompositionLocalProvider(LocalDensity provides Density(density = 1f, fontScale = 2f)) {
                val presentation = state.value
                DecryptOptionsCard(
                    viewModel = mainViewModel,
                    pcv3Presentation = presentation,
                    onSelectPcv3ConsentRole = { operationId, generation, role ->
                        val current = state.value as Pcv3Presentation.Live
                        assertCurrent(current, operationId, generation)
                        state.value = current.copy(consent = current.consent?.copy(selectedRole = role))
                    },
                    onConfirmPcv3Consent = { _, _ -> },
                    onRefusePcv3Consent = { _, _ -> },
                    modifier = Modifier.width(280.dp),
                )
                presentation?.let {
                    ProgressCard(
                        mainViewModel = mainViewModel,
                        operationViewModel = operationViewModel,
                        pcv3Presentation = it,
                        pcv3Intent = intent(Pcv3ActionIntent.RECOVERY),
                        onCancelPcv3 = { _, _ -> },
                        onClosePcv3Result = { operationId, generation ->
                            assertCurrent(state.value, operationId, generation)
                            state.value = null
                        },
                        onClosePcv3Archive = { operationId, generation ->
                            assertCurrent(state.value, operationId, generation)
                            state.value = final(
                                projectPcv3Snapshot(archive.close()),
                                operationId,
                                generation,
                            )
                        },
                        pcv3ArtifactDetails = artifactDetails.value,
                        onBeginPcv3Save = { operationId, generation ->
                            assertCurrent(state.value, operationId, generation)
                            "decrypted-output.pcv3-recovery"
                        },
                        onCompletePcv3Save = { _, _ -> },
                        onDiscardPcv3Output = { operationId, generation ->
                            assertCurrent(state.value, operationId, generation)
                            discardCalls += 1
                        },
                        onInspectPcv3Artifact = { operationId, generation ->
                            assertCurrent(state.value, operationId, generation)
                            inspectionCalls += 1
                            artifactDetails.value = if (inspectionCalls == 1) {
                                Pcv3ArtifactDetailsUiState.Loading
                            } else {
                                Pcv3ArtifactDetailsUiState.Ready(artifact, firstArtifactPage)
                            }
                        },
                        onLoadPcv3ArtifactPage = { operationId, generation, offset ->
                            assertCurrent(state.value, operationId, generation)
                            loadedOffsets += offset
                            artifactDetails.value = Pcv3ArtifactDetailsUiState.Ready(
                                artifact,
                                if (offset == "128") lastArtifactPage else firstArtifactPage,
                            )
                        },
                        onClosePcv3ArtifactInspection = { operationId, generation ->
                            assertCurrent(state.value, operationId, generation)
                            artifactDetails.value = Pcv3ArtifactDetailsUiState.Closed
                        },
                        modifier = Modifier.width(280.dp),
                    )
                }
            }
        }

        assertScrollableText(R.string.pcv3_consent_body)
        compose.onNodeWithText(text(R.string.pcv3_consent_cancel)).assertIsDisplayed()

        compose.runOnIdle {
            state.value = live(snapshot = workingSnapshot(Pcv3ProgressStatus.AUTHENTICATING))
        }
        compose.onNodeWithText(text(R.string.pcv3_progress_authenticating)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.pcv3_cancel_recovery)).assertIsDisplayed()

        compose.runOnIdle {
            state.value = live(
                snapshot = cleanSnapshot(),
                output = output,
                outputPending = true,
            )
        }
        compose.onNodeWithText(text(R.string.pcv3_save_decrypted_output)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.pcv3_save_recovery_artifact)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.pcv3_publication_close)).assertDoesNotExist()

        compose.runOnIdle {
            state.value = Pcv3Presentation.Final(
                snapshot = cleanSnapshot(),
                operationId = "terminal-operation",
                generation = 1,
                outputAction = Pcv3OutputResultView(
                    code = "saved-cleanup-incomplete",
                    cleanupIncomplete = true,
                ),
            )
        }
        assertScrollableText(R.string.pcv3_output_saved_cleanup_body)
        assertScrollableText(R.string.pcv3_outcome_success_body)
        assertScrollableText(R.string.pcv3_warning_cleanup_body)
        compose.onNodeWithText(text(R.string.pcv3_publication_durable_body)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.pcv3_warning_cleanup_close)).performClick()
        assertNull(state.value)

        compose.runOnIdle {
            state.value = live(
                snapshot = partialSnapshot(),
                output = output,
                outputPending = true,
                artifactMetadata = artifact,
            )
        }
        compose.onNodeWithText(text(R.string.pcv3_save_recovery_artifact)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.pcv3_inspect_recovery_artifact)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.pcv3_discard_recovery_artifact)).performClick()
        compose.onNodeWithText(text(R.string.pcv3_discard_artifact_body)).assertIsDisplayed()
        // The injected touch click re-entered touch mode; leave it again so
        // the dialog can grant the safe-default focus.
        leaveTouchMode()
        assertEventuallyFocused(text(R.string.pcv3_keep_recovery_artifact))
        compose.onNodeWithText(text(R.string.pcv3_keep_recovery_artifact)).performClick()
        assertEquals(0, discardCalls)

        compose.onNodeWithText(text(R.string.pcv3_discard_recovery_artifact)).performClick()
        compose.onNodeWithText(text(R.string.pcv3_discard_recovery_artifact)).performClick()
        assertEquals(1, discardCalls)

        compose.onNodeWithText(text(R.string.pcv3_inspect_recovery_artifact)).performClick()
        compose.onNodeWithText(text(R.string.pcv3_artifact_loading)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.pcv3_artifact_details_close)).performClick()
        compose.onNodeWithText(text(R.string.pcv3_inspect_recovery_artifact)).assertIsDisplayed()

        compose.onNodeWithText(text(R.string.pcv3_inspect_recovery_artifact)).performClick()
        compose.onNodeWithText(
            context.getString(
                R.string.pcv3_artifact_row,
                "0",
                "0",
                "9",
                text(R.string.pcv3_artifact_status_verified),
            ),
        ).performScrollTo().assertIsDisplayed()
        compose.onNodeWithText(text(R.string.pcv3_artifact_next_page)).performClick()
        assertEquals(listOf("128"), loadedOffsets)
        compose.onNodeWithText(
            context.getString(
                R.string.pcv3_artifact_row,
                "128",
                "1280",
                "1289",
                text(R.string.pcv3_artifact_status_missing),
            ),
        ).performScrollTo().assertIsDisplayed()
        compose.onNodeWithText(text(R.string.pcv3_artifact_previous_page)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.pcv3_artifact_details_close)).performClick()
        compose.onNodeWithText(text(R.string.pcv3_save_recovery_artifact)).assertIsDisplayed()

        compose.runOnIdle { state.value = live(snapshot = archivePendingSnapshot(), archive = archive) }
        assertScrollableText(R.string.pcv3_outcome_archive_pending_body)
        compose.onNodeWithText(text(R.string.pcv3_archive_close)).performClick()
        assertEquals(1, archive.closeCalls)
        assertEquals(0, archive.beginCalls)
        assertScrollableText(R.string.pcv3_publication_not_requested_body)
        compose.onNodeWithText(text(R.string.pcv3_outcome_generic_title)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.pcv3_publication_close)).performClick()
        assertNull(state.value)

        compose.runOnIdle {
            state.value = Pcv3Presentation.Restored(
                snapshot = uncertainSnapshot(),
                operationId = VALID_RECEIPT_OPERATION_ID,
                generation = 9,
                receiptId = VALID_RECEIPT_ID,
            )
        }
        assertScrollableText(R.string.pcv3_publication_uncertain_body)
        compose.onNodeWithText(text(R.string.pcv3_consent_confirm)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.pcv3_archive_close)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.pcv3_cancel_recovery)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.pcv3_publication_uncertain_close)).performClick()
        compose.onNodeWithTag(PCV3_RESULT_TAG).assertDoesNotExist()
        assertNull(state.value)
    }

    private fun assertScrollableText(resourceId: Int) {
        compose.onNodeWithText(text(resourceId)).performScrollTo().assertIsDisplayed()
    }

    private fun text(resourceId: Int): String = context.getString(resourceId)

    private fun newMainViewModel() = MainViewModel(
        ApplicationProvider.getApplicationContext<Application>(),
        SavedStateHandle(),
    )

    private fun indeterminateProgress(): SemanticsMatcher = SemanticsMatcher.expectValue(
        SemanticsProperties.ProgressBarRangeInfo,
        ProgressBarRangeInfo.Indeterminate,
    )

    private fun assertCurrent(
        presentation: Pcv3Presentation?,
        operationId: String,
        generation: Long,
    ) {
        assertEquals(presentation?.operationId, operationId)
        assertEquals(presentation?.generation, generation)
    }

    private fun intent(action: Pcv3ActionIntent) = Pcv3OperationIntent(
        format = Pcv3FormatIntent.NORMAL,
        action = action,
        factorPolicy = Pcv3FactorPolicyIntent.PASSWORD_ONLY,
    )

    private fun live(
        snapshot: Pcv3SnapshotView = workingSnapshot(),
        generation: Long = 1,
        operation: UiOperation = UiOperation("operation-$generation", snapshot),
        consent: UiConsent? = null,
        consentView: Pcv3ConsentView? = consent?.toViewOrNull(),
        archive: UiArchive? = null,
        output: Pcv3OutputCapability? = null,
        outputPending: Boolean = false,
        artifactMetadata: Pcv3ArtifactMetadataView? = null,
    ) = Pcv3Presentation.Live(
        snapshot = snapshot,
        operationId = operation.id,
        generation = generation,
        operationHandle = operation,
        consentHandle = consent,
        archiveHandle = archive,
        consent = consentView,
        outputHandle = output,
        outputPending = outputPending,
        artifactMetadata = artifactMetadata,
    )

    private fun final(
        snapshot: Pcv3SnapshotView,
        operationId: String = "terminal-operation",
        generation: Long = 1,
    ) = Pcv3Presentation.Final(snapshot, operationId, generation)

    private fun workingSnapshot(
        statusCode: String = "none",
        statusArgs: List<String> = emptyList(),
    ) = snapshot(statusCode = statusCode, statusArgs = statusArgs)

    private fun refusedSnapshot() = snapshot(
        semantic = Pcv3Semantic("operation-failed", "cancellation", "PCV3_OPERATION_FAILED"),
        diagnostic = "cancellation",
        completionClass = "refused",
    )

    private fun resourceSnapshot(diagnostic: String) = snapshot(
        semantic = Pcv3Semantic(
            "operation-failed",
            "credential-policy",
            "PCV3_OPERATION_FAILED",
        ),
        diagnostic = diagnostic,
        completionClass = "refused",
    )

    private fun cleanSnapshot() = snapshot(
        semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
        publication = Pcv3Publication(
            attempted = true,
            state = "published-durable",
            stage = "none",
            code = "PCV3_PUBLICATION_PUBLISHED_DURABLE",
        ),
        completionClass = "clean",
    )

    private fun partialSnapshot() = snapshot(
        semantic = Pcv3Semantic("force-partial", "record-auth", "PCV3_FORCE_PARTIAL"),
        publication = Pcv3Publication(
            attempted = true,
            state = "published-durable",
            stage = "none",
            code = "PCV3_PUBLICATION_PUBLISHED_DURABLE",
        ),
        completionClass = "warning",
        warnings = listOf("force-partial"),
    ).copy(forceProvenance = "partial")

    private fun artifactMetadata() = Pcv3ArtifactMetadataView(
        kind = "partial",
        role = "none",
        plaintextLength = "1290",
        finalStatus = "missing",
        rangeCount = "129",
        verifiedCount = "128",
        unverifiedCount = "0",
        missingCount = "1",
    )

    private fun archivePendingSnapshot() = snapshot(
        semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
        completionClass = "archive-pending",
        archivePending = true,
    )

    private fun archiveClosedSnapshot() = snapshot(
        semantic = Pcv3Semantic(
            "operation-failed",
            "output-publication",
            "PCV3_OPERATION_FAILED",
        ),
        completionClass = "no-output",
    )

    private fun uncertainSnapshot() = snapshot(
        semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
        publication = Pcv3Publication(
            attempted = true,
            state = "published-durability-uncertain",
            stage = "directory-sync",
            code = "PCV3_PUBLICATION_DURABILITY_UNCERTAIN",
        ),
        completionClass = "durability-uncertain",
        warnings = listOf("cleanup-incomplete", "durability-uncertain"),
        restoredReceipt = VALID_RECEIPT,
    ).copy(
        forceProvenance = "verified",
        d1BootstrapProvenance = "matching",
        detailStage = "metadata",
        resultArgs = listOf("7", "11", "13", "17"),
    )

    private fun snapshot(
        statusCode: String = "none",
        statusArgs: List<String> = emptyList(),
        semantic: Pcv3Semantic = Pcv3Semantic("unknown-outcome", "none", "PCV3_UNKNOWN"),
        publication: Pcv3Publication = Pcv3Publication(false, "none", "none", "none"),
        diagnostic: String = "none",
        completionClass: String = "unknown",
        warnings: List<String> = emptyList(),
        archivePending: Boolean = false,
        restoredReceipt: String = "",
    ) = Pcv3SnapshotView(
        statusCode = statusCode,
        statusArgs = statusArgs,
        semantic = semantic,
        publication = publication,
        forceProvenance = "none",
        d1BootstrapProvenance = "none",
        detailStage = "none",
        diagnostic = diagnostic,
        completionClass = completionClass,
        resultArgs = emptyList(),
        warnings = warnings,
        archivePending = archivePending,
        restoredReceipt = restoredReceipt,
    )

    private fun Pcv3SnapshotView.toData() = Pcv3SnapshotData(
        statusCode = statusCode,
        statusArgs = statusArgs,
        outcome = semantic.outcome,
        stage = semantic.stage,
        code = semantic.code,
        forceProvenance = forceProvenance,
        d1BootstrapProvenance = d1BootstrapProvenance,
        detailStage = detailStage,
        publicationAttempted = publication.attempted,
        publicationState = publication.state,
        publicationStage = publication.stage,
        publicationCode = publication.code,
        diagnostic = diagnostic,
        completionClass = completionClass,
        args = resultArgs,
        warnings = warnings,
        archivePending = archivePending,
        restoredReceipt = restoredReceipt,
    )

    private inner class UiOperation(
        override val id: String,
        snapshot: Pcv3SnapshotView,
    ) : Pcv3OperationCapability {
        private var current = snapshot.toData()
        var live = true
            private set
        var cancelCalls = 0
            private set

        override fun snapshot(): Pcv3SnapshotData = current
        override fun consent(): Pcv3ConsentCapability? = null
        override fun archive(): Pcv3ArchiveCapability? = null
        override fun cancel(): Pcv3SnapshotData {
            check(live)
            cancelCalls += 1
            live = false
            current = refusedSnapshot().toData()
            return current
        }
        override fun release(): String {
            live = false
            return ""
        }
    }

    private class UiConsent(
        private val modeValue: String,
        private val rolesValue: List<String>,
    ) : Pcv3ConsentCapability {
        var live = true
            private set
        var chooseCalls = 0
            private set
        var refuseCalls = 0
            private set

        override fun mode(): String = modeValue
        override fun roles(): List<String> = rolesValue
        override fun choose(role: String): String {
            chooseCalls += 1
            if (!live || role !in rolesValue) return "PCV3_CONSENT_EXPIRED"
            live = false
            return ""
        }
        override fun refuse(): String {
            refuseCalls += 1
            if (!live) return "PCV3_CONSENT_EXPIRED"
            live = false
            return ""
        }
    }

    private inner class UiArchive(terminal: Pcv3SnapshotView) : Pcv3ArchiveCapability {
        override fun cancelPreparation() = Unit
        private val terminalData = terminal.toData()
        private var live = true
        var closeCalls = 0
            private set
        var beginCalls = 0
            private set

        override fun close(): Pcv3SnapshotData {
            check(live)
            live = false
            closeCalls += 1
            return terminalData
        }
        override fun beginSaf(): Pcv3ArchiveBeginData {
            beginCalls += 1
            live = false
            return Pcv3ArchiveBeginData("terminal", terminalData.code, null, terminalData)
        }
    }

    private class UiOutput : Pcv3OutputCapability {
        override fun save(destination: android.os.ParcelFileDescriptor): Pcv3OutputResultData {
            error("CreateDocument is not launched by this display-only contract")
        }

        override fun discard(): Pcv3OutputResultData {
            error("Discard remains routed through the ViewModel callback")
        }
    }

    private companion object {
        const val FOCUS_TIMEOUT_MILLIS = 5_000L
        const val VALID_RECEIPT_ID = "r_00112233445566778899aabbccddeeff"
        const val VALID_RECEIPT_OPERATION_ID = "op_1700000000000000000_7"
        const val VALID_RECEIPT = "{\"version\":1,\"receiptID\":\"r_00112233445566778899aabbccddeeff\",\"operationID\":\"op_1700000000000000000_7\",\"outcome\":7,\"stage\":0,\"code\":7,\"forceProvenance\":1,\"d1BootstrapProvenance\":3,\"detailStage\":13,\"publicationAttempted\":true,\"publicationState\":3,\"publicationStage\":24,\"publicationCode\":9,\"args\":[7,11,13,17],\"warnings\":[6,4],\"diagnostic\":0}"
    }
}
