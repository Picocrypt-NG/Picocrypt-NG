package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.content.res.Resources
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test

class OperationStatusTest {
    @Test
    fun `save error is visible with retained result while cleanup stays deferred`() {
        val presentation = Pcv3Presentation.Live(
            snapshot = snapshot(semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
                publication = durablePublication(), completionClass = "clean"),
            operationId = "retained", generation = 1,
            operationHandle = mockk(relaxed = true), consentHandle = null, archiveHandle = null,
            consent = null, outputHandle = mockk(relaxed = true), outputPending = true,
        )
        val saveError = AppError.FileError.SaveFailed()
        val cleanupError = AppError.FileError.DeleteFailed()
        assertEquals(saveError, pcv3VisibleError(saveError, presentation))
        assertEquals(null, pcv3VisibleError(cleanupError, presentation))
        assertEquals(cleanupError, pcv3VisibleError(cleanupError, null))
    }

    @Test
    fun `every static status code resolves through its matching resource`() {
        val context = mockk<Context>()
        staticStatusResources.forEach { (code, resourceId) ->
            every { context.getString(resourceId) } returns "localized:$code"

            assertEquals(
                OperationDisplayText(status = "localized:$code"),
                renderOperationStatus(
                    context = context,
                    status = OperationStatusData(code),
                    detail = OperationProgressDetail("NONE"),
                    progress = 0f,
                ),
            )
        }
    }

    @Test
    fun `every rate status code formats validated speed and ETA through its resource`() {
        val context = mockk<Context>()
        rateStatusResources.forEach { (code, resourceId) ->
            every { context.getString(resourceId, 12.34, "01:02:03") } returns "localized:$code"

            assertEquals(
                OperationDisplayText(status = "localized:$code"),
                renderOperationStatus(
                    context = context,
                    status = OperationStatusData(code, 12.34, "01:02:03"),
                    detail = OperationProgressDetail("NONE"),
                    progress = 0f,
                ),
            )
            verify(exactly = 1) { context.getString(resourceId, 12.34, "01:02:03") }
        }
    }

    @Test
    fun `rate status accepts producer valid ETA above 99 hours`() {
        val context = mockk<Context>()
        every {
            context.getString(R.string.status_encrypting_rate, 12.34, "100:59:59")
        } returns "localized:long-running-encryption"
        every { context.getString(R.string.fgs_working) } returns "localized:working"

        assertEquals(
            OperationDisplayText(status = "localized:long-running-encryption"),
            renderOperationStatus(
                context = context,
                status = OperationStatusData(
                    OperationStatus.ENCRYPTING_RATE,
                    12.34,
                    "100:59:59",
                ),
                detail = OperationProgressDetail(OperationProgress.NONE),
                progress = 0f,
            ),
        )
    }

    @Test
    fun `percent detail delegates locale aware decimal formatting to Android resources`() {
        val context = mockk<Context>()
        every { context.getString(R.string.status_encrypting_rate, 1.25, "00:00:09") } returns "Шифрование"
        every { context.getString(R.string.progress_percent, 37.5) } returns "37,50 %"

        val result = renderOperationStatus(
            context = context,
            status = OperationStatusData("ENCRYPTING_RATE", 1.25, "00:00:09"),
            detail = OperationProgressDetail("PERCENT"),
            progress = 0.375f,
        )

        assertEquals(OperationDisplayText("Шифрование", "37,50 %"), result)
        verify(exactly = 1) { context.getString(R.string.progress_percent, 37.5) }
    }

    @Test
    fun `item count detail uses the localized plural selected by total`() {
        val context = mockk<Context>()
        val resources = mockk<Resources>()
        every { context.getString(R.string.status_compressing_files) } returns "Compressing"
        every { context.resources } returns resources
        every {
            resources.getQuantityString(R.plurals.progress_item_count, 10, 3L, 10L)
        } returns "3 of 10 items"

        val result = renderOperationStatus(
            context = context,
            status = OperationStatusData("COMPRESSING_FILES"),
            detail = OperationProgressDetail("ITEM_COUNT", current = 3, total = 10),
            progress = 0.3f,
        )

        assertEquals(OperationDisplayText("Compressing", "3 of 10 items"), result)
        verify(exactly = 1) {
            resources.getQuantityString(R.plurals.progress_item_count, 10, 3L, 10L)
        }
    }

    @Test
    fun `unknown status degrades to working while unknown detail stays hidden`() {
        val context = mockk<Context>()
        every { context.getString(R.string.fgs_working) } returns "Working safely"

        val result = renderOperationStatus(
            context = context,
            status = OperationStatusData("UNKNOWN"),
            detail = OperationProgressDetail("UNKNOWN"),
            progress = 0.5f,
        )

        assertEquals(OperationDisplayText("Working safely", null), result)
    }

    @Test
    fun `none detail stays hidden`() {
        val context = mockk<Context>()
        every { context.getString(R.string.status_starting) } returns "Starting"

        val result = renderOperationStatus(
            context = context,
            status = OperationStatusData("STARTING"),
            detail = OperationProgressDetail("NONE"),
            progress = 0f,
        )

        assertNull(result.detail)
    }

    @Test
    fun `malformed rate arguments degrade to working instead of interpolation`() {
        val context = mockk<Context>()
        every { context.getString(R.string.fgs_working) } returns "Working safely"
        val malformed = listOf(
            OperationStatusData("ENCRYPTING_RATE", Double.NaN, "01:02:03"),
            OperationStatusData("ENCRYPTING_RATE", Double.POSITIVE_INFINITY, "01:02:03"),
            OperationStatusData("ENCRYPTING_RATE", -0.01, "01:02:03"),
            OperationStatusData("ENCRYPTING_RATE", 1.0, "1:02:03"),
            OperationStatusData("ENCRYPTING_RATE", 1.0, "01:60:03"),
            OperationStatusData("ENCRYPTING_RATE", 1.0, "01:02:60"),
        )

        malformed.forEach { status ->
            assertEquals(
                "Working safely",
                renderOperationStatus(
                    context,
                    status,
                    OperationProgressDetail("NONE"),
                    progress = 0f,
                ).status,
            )
        }
        verify(exactly = 0) {
            context.getString(R.string.status_encrypting_rate, any(), any())
        }
    }

    @Test
    fun `malformed progress arguments stay hidden`() {
        val context = mockk<Context>()
        every { context.getString(R.string.status_starting) } returns "Starting"
        val malformed = listOf(
            OperationProgressDetail("PERCENT") to Float.NaN,
            OperationProgressDetail("PERCENT") to -0.01f,
            OperationProgressDetail("PERCENT") to 1.01f,
            OperationProgressDetail("ITEM_COUNT", current = -1, total = 10) to 0f,
            OperationProgressDetail("ITEM_COUNT", current = 11, total = 10) to 0f,
            OperationProgressDetail("ITEM_COUNT", current = 0, total = 0) to 0f,
            OperationProgressDetail(
                "ITEM_COUNT",
                current = 1,
                total = Int.MAX_VALUE.toLong() + 1,
            ) to 0f,
        )

        malformed.forEach { (detail, progress) ->
            assertNull(
                renderOperationStatus(
                    context,
                    OperationStatusData("STARTING"),
                    detail,
                    progress,
                ).detail,
            )
        }
    }

    @Test
    fun `PCV3 progress accepts closed codes and the specified bounded recovery tuple`() {
        pcv3ProgressResources.forEach { (code, resourceId) ->
            assertEquals(
                Pcv3ProgressDisplay(resourceId),
                pcv3ProgressDisplay(snapshot(statusCode = code)),
            )
        }

        assertEquals(
            Pcv3ProgressDisplay(R.string.pcv3_progress_recovering, fraction = 0.25f),
            pcv3ProgressDisplay(
                snapshot(
                    statusCode = Pcv3ProgressStatus.RECOVERING,
                    statusArgs = listOf("1", "4"),
                ),
            ),
        )
    }

    @Test
    fun `PCV3 malformed or unknown progress stays neutral and indeterminate`() {
        val invalid = listOf(
            snapshot(statusCode = "attacker-progress"),
            snapshot(statusCode = Pcv3ProgressStatus.DERIVING_KEY, statusArgs = listOf("1")),
            snapshot(statusCode = Pcv3ProgressStatus.RECOVERING, statusArgs = listOf("1")),
            snapshot(statusCode = Pcv3ProgressStatus.RECOVERING, statusArgs = listOf("-1", "4")),
            snapshot(
                statusCode = Pcv3ProgressStatus.RECOVERING,
                statusArgs = listOf("18446744073709551616", "18446744073709551616"),
            ),
            snapshot(statusCode = Pcv3ProgressStatus.RECOVERING, statusArgs = listOf("5", "4")),
            snapshot(statusCode = Pcv3ProgressStatus.RECOVERING, statusArgs = listOf("0", "0")),
            snapshot(
                statusCode = Pcv3ProgressStatus.RECOVERING,
                statusArgs = listOf("1", "4", "unexpected"),
            ),
        )

        invalid.forEach {
            assertEquals(
                Pcv3ProgressDisplay(R.string.pcv3_progress_working),
                pcv3ProgressDisplay(it),
            )
        }
    }

    @Test
    fun `PCV3 semantic success and uncertain publication remain separate`() {
        val display = pcv3ResultDisplay(
            snapshot(
                semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
                publication = Pcv3Publication(
                    attempted = true,
                    state = "published-durability-uncertain",
                    stage = "directory-sync",
                    code = "PCV3_PUBLICATION_DURABILITY_UNCERTAIN",
                ),
                completionClass = "durability-uncertain",
                warnings = listOf("durability-uncertain"),
            ),
        )

        assertEquals(R.string.pcv3_outcome_success_title, display.outcome.titleResId)
        assertEquals(R.string.pcv3_publication_uncertain_title, display.publication?.titleResId)
        assertEquals(Pcv3ResultTone.WARNING, display.tone)
        assertEquals(R.string.pcv3_publication_uncertain_close, display.closeActionResId)

        val indeterminate = snapshot(
            semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
            publication = Pcv3Publication(
                attempted = true,
                state = "publication-indeterminate",
                stage = "rename",
                code = "PCV3_PUBLICATION_INDETERMINATE",
            ),
            completionClass = "publication-indeterminate",
            warnings = listOf("cleanup-incomplete", "publication-indeterminate"),
        )
        val indeterminateDisplay = pcv3ResultDisplay(indeterminate)
        val indeterminatePresentation = Pcv3Presentation.Final(
            snapshot = indeterminate,
            operationId = "indeterminate",
            generation = 4,
            outputAction = Pcv3OutputResultView(
                code = "saved-cleanup-incomplete",
                cleanupIncomplete = true,
            ),
        )
        val indeterminateActionDisplay = pcv3ResultDisplay(indeterminatePresentation)
        val indeterminateActions = pcv3ResultActions(indeterminatePresentation)

        assertEquals(Pcv3ResultTone.ERROR, indeterminateDisplay.tone)
        assertEquals(
            R.string.pcv3_publication_indeterminate_close,
            indeterminateDisplay.closeActionResId,
        )
        assertEquals(
            R.string.pcv3_publication_indeterminate_title,
            indeterminateActionDisplay.publication?.titleResId,
        )
        assertEquals(
            R.string.pcv3_output_unknown_title,
            indeterminateActionDisplay.supportingOutcome?.titleResId,
        )
        assertEquals(
            listOf(R.string.pcv3_warning_cleanup_title),
            indeterminateActionDisplay.warnings.map(Pcv3CopyResources::titleResId),
        )
        assertEquals(
            R.string.pcv3_publication_indeterminate_close,
            indeterminateActionDisplay.closeActionResId,
        )
        assertEquals(setOf(Pcv3ResultAction.CLOSE_RESULT), indeterminateActions.actions)
        assertEquals(
            R.string.pcv3_publication_indeterminate_close,
            indeterminateActions.closeActionResId,
        )
    }

    @Test
    fun `authenticated PCV3 comment survives result and output-action projection`() {
        val authenticated = snapshot(
            semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
            publication = durablePublication(),
            completionClass = "clean",
            authenticatedComment = "public authenticated note",
        )
        assertEquals("public authenticated note", pcv3ResultDisplay(authenticated).authenticatedComment)

        val saved = Pcv3Presentation.Final(
            snapshot = authenticated,
            operationId = "comment-output",
            generation = 1,
            outputAction = Pcv3OutputResultView("saved", cleanupIncomplete = false),
        )
        assertEquals("public authenticated note", pcv3ResultDisplay(saved).authenticatedComment)
        assertNull(pcv3ResultDisplay(snapshot()).authenticatedComment)
    }

    @Test
    fun `PCV3 resource refusal permits only its fixed no-output dismissal`() {
        resourceNotices.forEach { (diagnostic, expectedTitle) ->
            val display = pcv3ResultDisplay(
                snapshot(
                    semantic = Pcv3Semantic(
                        "operation-failed",
                        if (diagnostic == "resource-limit") "resource-budget" else "credential-policy",
                        "PCV3_OPERATION_FAILED",
                    ),
                    diagnostic = diagnostic,
                    completionClass = "refused",
                ),
            )

            assertEquals(expectedTitle, display.outcome.titleResId)
            assertNull(display.publication)
            assertEquals(Pcv3ResultTone.WARNING, display.tone)
            assertEquals(R.string.pcv3_resource_close, display.closeActionResId)
        }
    }

    @Test
    fun `PCV3 unknown result values never become displayed attacker text`() {
        val display = pcv3ResultDisplay(
            snapshot(
                semantic = Pcv3Semantic(
                    "PRIVATE path and raw error",
                    "PRIVATE stage",
                    "PRIVATE code",
                ),
                publication = Pcv3Publication(
                    attempted = true,
                    state = "PRIVATE publication",
                    stage = "PRIVATE stage",
                    code = "PRIVATE code",
                ),
                diagnostic = "PRIVATE diagnostic",
                warnings = listOf("PRIVATE warning"),
                completionClass = "unknown",
            ),
        )

        assertEquals(R.string.pcv3_outcome_generic_title, display.outcome.titleResId)
        assertNull(display.publication)
        assertEquals(
            listOf(R.string.pcv3_warning_unknown_title),
            display.warnings.map(Pcv3CopyResources::titleResId),
        )
        assertEquals(Pcv3ResultTone.ERROR, display.tone)
        assertEquals(R.string.pcv3_publication_close, display.closeActionResId)
    }

    @Test
    fun `PCV3 final output action pairs change bounded terminal truth and expose cleanup uncertainty`() {
        data class Case(
            val result: Pcv3OutputResultView,
            val titleResId: Int,
            val tone: Pcv3ResultTone,
            val closeResId: Int,
            val snapshot: Pcv3SnapshotView,
            val artifactMetadata: Pcv3ArtifactMetadataView? = null,
        )
        val terminalSnapshot = snapshot(
            semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
            publication = durablePublication(),
            completionClass = "clean",
        )
        val recoveryMetadata = artifactMetadata("partial")
        val recoverySnapshot = snapshot(
            semantic = Pcv3Semantic("force-partial", "record-auth", "PCV3_FORCE_PARTIAL"),
            publication = durablePublication(),
            forceProvenance = "partial",
            completionClass = "warning",
            warnings = listOf("force-partial"),
        )
        val cases = listOf(
            Case(
                Pcv3OutputResultView("saved", cleanupIncomplete = false),
                R.string.pcv3_output_saved_title,
                Pcv3ResultTone.NEUTRAL,
                R.string.pcv3_output_saved_close,
                terminalSnapshot,
            ),
            Case(
                Pcv3OutputResultView("saved-cleanup-incomplete", cleanupIncomplete = true),
                R.string.pcv3_output_saved_cleanup_title,
                Pcv3ResultTone.WARNING,
                R.string.pcv3_warning_cleanup_close,
                terminalSnapshot,
            ),
            Case(
                Pcv3OutputResultView("save-failed", cleanupIncomplete = false),
                R.string.pcv3_output_save_failed_title,
                Pcv3ResultTone.ERROR,
                R.string.pcv3_output_save_failed_close,
                terminalSnapshot,
            ),
            Case(
                Pcv3OutputResultView("save-failed-cleanup-incomplete", cleanupIncomplete = true),
                R.string.pcv3_output_save_failed_cleanup_title,
                Pcv3ResultTone.ERROR,
                R.string.pcv3_warning_cleanup_close,
                terminalSnapshot,
            ),
            Case(
                Pcv3OutputResultView("discarded", cleanupIncomplete = false),
                R.string.pcv3_output_discarded_title,
                Pcv3ResultTone.NEUTRAL,
                R.string.pcv3_output_discarded_close,
                recoverySnapshot,
                recoveryMetadata,
            ),
            Case(
                Pcv3OutputResultView("discard-cleanup-incomplete", cleanupIncomplete = true),
                R.string.pcv3_output_discard_cleanup_title,
                Pcv3ResultTone.WARNING,
                R.string.pcv3_warning_cleanup_close,
                recoverySnapshot,
                recoveryMetadata,
            ),
            Case(
                Pcv3OutputResultView("expired", cleanupIncomplete = false),
                R.string.pcv3_output_expired_title,
                Pcv3ResultTone.ERROR,
                R.string.pcv3_output_expired_close,
                terminalSnapshot,
            ),
        )
        val displays = cases.mapIndexed { index, case ->
            val presentation = Pcv3Presentation.Final(
                snapshot = case.snapshot,
                operationId = "settled-$index",
                generation = index.toLong(),
                outputAction = case.result,
                artifactMetadata = case.artifactMetadata,
            )
            pcv3ResultDisplay(presentation)
        }

        assertEquals(
            "each closed code/cleanup pair must remain distinguishable in the terminal projection",
            cases.size,
            displays.toSet().size,
        )
        cases.zip(displays).forEach { (case, display) ->
            assertEquals(case.titleResId, display.outcome.titleResId)
            assertEquals(case.tone, display.tone)
            assertEquals(case.closeResId, display.closeActionResId)
            assertEquals(
                case.result.cleanupIncomplete,
                display.warnings.any { it.titleResId == R.string.pcv3_warning_cleanup_title },
            )
            assertNull(display.publication)
            assertEquals(
                case.result.code.startsWith("saved"),
                display.supportingOutcome != null,
            )
        }

        cases.take(4).forEachIndexed { index, case ->
            val recoverySave = Pcv3Presentation.Final(
                snapshot = recoverySnapshot,
                operationId = "recovery-save-$index",
                generation = 100L + index,
                outputAction = case.result,
                artifactMetadata = recoveryMetadata,
            )
            assertEquals(case.titleResId, pcv3ResultDisplay(recoverySave).outcome.titleResId)
        }
    }

    @Test
    fun `PCV3 decrypted output discard reports ordinary cleanup without recovery copy`() {
        val decrypted = snapshot(
            semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
            publication = durablePublication(),
            completionClass = "clean",
        )
        val discarded = pcv3ResultDisplay(
            Pcv3Presentation.Final(
                snapshot = decrypted,
                operationId = "decrypted-discarded",
                generation = 201,
                outputAction = Pcv3OutputResultView("discarded", cleanupIncomplete = false),
            ),
        )
        val cleanupIncomplete = pcv3ResultDisplay(
            Pcv3Presentation.Final(
                snapshot = decrypted,
                operationId = "decrypted-discard-cleanup",
                generation = 202,
                outputAction = Pcv3OutputResultView(
                    "discard-cleanup-incomplete",
                    cleanupIncomplete = true,
                ),
            ),
        )

        assertEquals(R.string.pcv3_retained_discarded_title, discarded.outcome.titleResId)
        assertEquals(R.string.pcv3_output_discarded_close, discarded.closeActionResId)
        assertEquals(emptyList<Pcv3CopyResources>(), discarded.warnings)
        assertEquals(R.string.pcv3_retained_discard_cleanup_title, cleanupIncomplete.outcome.titleResId)
        assertEquals(R.string.pcv3_warning_cleanup_close, cleanupIncomplete.closeActionResId)
        assertEquals(
            listOf(R.string.pcv3_warning_cleanup_title),
            cleanupIncomplete.warnings.map(Pcv3CopyResources::titleResId),
        )
    }

    @Test
    fun `PCV3 unknown and contradictory output action pairs share one bounded warning state`() {
        val terminalSnapshot = snapshot(
            semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
            publication = durablePublication(),
            completionClass = "clean",
        )
        val invalidPairs = listOf(
            Pcv3OutputResultView("saved", cleanupIncomplete = true),
            Pcv3OutputResultView("saved-cleanup-incomplete", cleanupIncomplete = false),
            Pcv3OutputResultView("save-failed", cleanupIncomplete = true),
            Pcv3OutputResultView("save-failed-cleanup-incomplete", cleanupIncomplete = false),
            Pcv3OutputResultView("discarded", cleanupIncomplete = true),
            Pcv3OutputResultView("discard-cleanup-incomplete", cleanupIncomplete = false),
            Pcv3OutputResultView("expired", cleanupIncomplete = true),
            Pcv3OutputResultView("PRIVATE path and error", cleanupIncomplete = false),
            Pcv3OutputResultView("PRIVATE path and error", cleanupIncomplete = true),
        )
        val displays = invalidPairs.mapIndexed { index, result ->
            val presentation = Pcv3Presentation.Final(
                snapshot = terminalSnapshot,
                operationId = "invalid-settlement-$index",
                generation = index.toLong(),
                outputAction = result,
            )
            pcv3ResultDisplay(presentation)
        }

        assertEquals(1, displays.map { it.outcome }.toSet().size)
        displays.forEachIndexed { index, display ->
            val result = invalidPairs[index]
            val cleanupUncertain = result.cleanupIncomplete ||
                result.code.endsWith("-cleanup-incomplete")
            assertEquals(R.string.pcv3_output_unknown_title, display.outcome.titleResId)
            assertEquals(Pcv3ResultTone.ERROR, display.tone)
            assertEquals(
                cleanupUncertain,
                display.warnings.any { it.titleResId == R.string.pcv3_warning_cleanup_title },
            )
            assertEquals(
                if (cleanupUncertain) {
                    R.string.pcv3_warning_cleanup_close
                } else {
                    R.string.pcv3_output_unknown_close
                },
                display.closeActionResId,
            )
            assertNull(display.supportingOutcome)
            assertNull(display.publication)
        }
        assertNotEquals(
            "unknown action truth must not reuse the clean pre-action success result",
            pcv3ResultDisplay(terminalSnapshot).outcome,
            displays.first().outcome,
        )
    }

    @Test
    fun `PCV3 result actions are capability bound deny uncertainty and navigate only checked pages`() {
        val operation = mockk<Pcv3OperationCapability>(relaxed = true)
        val output = mockk<Pcv3OutputCapability>(relaxed = true)
        val cleanLive = Pcv3Presentation.Live(
            snapshot = snapshot(
                semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
                publication = durablePublication(),
                completionClass = "clean",
            ),
            operationId = "clean-live",
            generation = 1,
            operationHandle = operation,
            consentHandle = null,
            archiveHandle = null,
            consent = null,
            outputHandle = output,
            outputPending = true,
        )
        val artifact = artifactMetadata("partial")
        val forceLive = cleanLive.copy(
            snapshot = snapshot(
                semantic = Pcv3Semantic("force-partial", "record-auth", "PCV3_FORCE_PARTIAL"),
                publication = durablePublication(),
                forceProvenance = "partial",
                completionClass = "warning",
                warnings = listOf("force-partial"),
            ),
            artifactMetadata = artifact,
        )
        val nearMissForceLive = forceLive.copy(
            snapshot = forceLive.snapshot.copy(forceProvenance = "none"),
        )
        val uncertain = Pcv3Presentation.Final(
            snapshot = snapshot(
                semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
                publication = Pcv3Publication(
                    attempted = true,
                    state = "published-durability-uncertain",
                    stage = "directory-sync",
                    code = "PCV3_PUBLICATION_DURABILITY_UNCERTAIN",
                ),
                completionClass = "durability-uncertain",
                warnings = listOf("cleanup-incomplete", "durability-uncertain"),
            ),
            operationId = "uncertain",
            generation = 2,
        )
        val forceFinal = Pcv3Presentation.Final(
            snapshot = forceLive.snapshot,
            operationId = "force-final",
            generation = 3,
            artifactMetadata = artifact,
        )
        val contradictoryFinal = forceFinal.copy(
            snapshot = forceFinal.snapshot.copy(
                semantic = Pcv3Semantic("force-unverified", "record-auth", "PCV3_FORCE_UNVERIFIED"),
            ),
        )

        assertEquals(
            setOf(Pcv3ResultAction.SAVE_DECRYPTED_OUTPUT, Pcv3ResultAction.DISCARD_OUTPUT),
            pcv3ResultActions(cleanLive).actions,
        )
        assertEquals(
            setOf(
                Pcv3ResultAction.SAVE_RECOVERY_ARTIFACT,
                Pcv3ResultAction.INSPECT_RECOVERY_ARTIFACT,
                Pcv3ResultAction.DISCARD_RECOVERY_ARTIFACT,
            ),
            pcv3ResultActions(forceLive).actions,
        )
        assertEquals(emptySet<Pcv3ResultAction>(), pcv3ResultActions(nearMissForceLive).actions)
        assertEquals(
            setOf(Pcv3ResultAction.CLOSE_RESULT),
            pcv3ResultActions(uncertain).actions,
        )
        assertEquals(
            R.string.pcv3_publication_uncertain_close,
            pcv3ResultActions(uncertain).closeActionResId,
        )
        assertEquals(
            setOf(Pcv3ResultAction.INSPECT_RECOVERY_ARTIFACT, Pcv3ResultAction.CLOSE_RESULT),
            pcv3ResultActions(forceFinal).actions,
        )
        assertEquals(
            setOf(Pcv3ResultAction.CLOSE_RESULT),
            pcv3ResultActions(contradictoryFinal).actions,
        )

        val firstPage = Pcv3ArtifactPageView(
            offsetDecimal = "0",
            ranges = (0 until 128).map { index ->
                Pcv3ArtifactRangeView(index.toString(), index.toString(), (index + 1).toString(), "verified")
            },
        )
        assertEquals(
            Pcv3ArtifactPageNavigation(previousOffsetDecimal = null, nextOffsetDecimal = "128"),
            pcv3ArtifactPageNavigation(artifact.copy(rangeCount = "129"), firstPage),
        )
        assertNull(
            pcv3ArtifactPageNavigation(
                artifact.copy(rangeCount = "129"),
                firstPage.copy(offsetDecimal = "01"),
            ),
        )
    }

    @Test
    fun `PCV3 creation shows creation copy and binds save to the created volume`() {
        val operation = mockk<Pcv3OperationCapability>(relaxed = true)
        val output = mockk<Pcv3OutputCapability>(relaxed = true)
        val creationSnapshot = snapshot(
            semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
            publication = durablePublication(),
            completionClass = "clean",
        )
        // A normal creation keeps the retained output capability until Save settles it.
        val liveCreation = Pcv3Presentation.Live(
            snapshot = creationSnapshot,
            operationId = "create-live",
            generation = 1,
            operationHandle = operation,
            consentHandle = null,
            archiveHandle = null,
            consent = null,
            outputHandle = output,
            outputPending = true,
            isCreation = true,
        )
        assertEquals(
            setOf(Pcv3ResultAction.SAVE_CREATED_VOLUME, Pcv3ResultAction.DISCARD_OUTPUT),
            pcv3ResultActions(liveCreation).actions,
        )
        // A creation without a settled output action shows creation copy, never decryption copy.
        val creationDisplay = pcv3ResultDisplay(liveCreation)
        assertEquals(R.string.pcv3_create_outcome_title, creationDisplay.outcome.titleResId)
        assertEquals(R.string.pcv3_create_outcome_body, creationDisplay.outcome.bodyResId)
        assertNull(creationDisplay.publication)

        // Scalar terminal success cannot recreate output authority for either codec.
        val d1Final = Pcv3Presentation.Final(
            snapshot = creationSnapshot,
            operationId = "create-d1-final",
            generation = 2,
            isCreation = true,
        )
        assertEquals(
            setOf(Pcv3ResultAction.CLOSE_RESULT),
            pcv3ResultActions(d1Final).actions,
        )
        assertEquals(
            R.string.pcv3_create_outcome_title,
            pcv3ResultDisplay(d1Final).outcome.titleResId,
        )

        // A creation that did not reach the exact clean durable success offers no save.
        val failedFinal = d1Final.copy(
            snapshot = creationSnapshot.copy(
                semantic = Pcv3Semantic("operation-failed", "input-io", "PCV3_OPERATION_FAILED"),
            ),
        )
        assertEquals(setOf(Pcv3ResultAction.CLOSE_RESULT), pcv3ResultActions(failedFinal).actions)
    }

    @Test
    fun `PCV3 uncertain creation offers capability bound save while retaining its warning and receipt`() {
        val uncertain = snapshot(
            semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
            publication = Pcv3Publication(true, "published-durability-uncertain", "directory-sync", "PCV3_PUBLICATION_DURABILITY_UNCERTAIN"),
            completionClass = "durability-uncertain",
            warnings = listOf("durability-uncertain"),
            restoredReceipt = "terminal-receipt",
        )
        val live = Pcv3Presentation.Live(
            snapshot = uncertain,
            operationId = "uncertain-creation", generation = 1,
            operationHandle = mockk(relaxed = true), consentHandle = null, archiveHandle = null, consent = null,
            outputHandle = mockk(relaxed = true), outputPending = true, isCreation = true,
        )

        assertEquals(Pcv3OutputActionTarget.CREATED_VOLUME, pcv3OutputActionTarget(uncertain, null, isCreation = true))
        assertEquals(setOf(Pcv3ResultAction.SAVE_CREATED_VOLUME, Pcv3ResultAction.DISCARD_OUTPUT), pcv3ResultActions(live).actions)
        val display = pcv3ResultDisplay(live)
        assertEquals(Pcv3ResultTone.WARNING, display.tone)
        assertEquals(R.string.pcv3_publication_uncertain_title, display.publication?.titleResId)
        assertEquals(R.string.pcv3_publication_uncertain_body, display.publication?.bodyResId)
        assertEquals(R.string.pcv3_publication_uncertain_close, display.closeActionResId)
        for (denied in listOf(
            live.copy(isCreation = false),
            live.copy(outputHandle = null),
            live.copy(outputActionInFlight = true),
            live.copy(snapshot = uncertain.copy(restoredReceipt = "")),
            live.copy(snapshot = uncertain.copy(publication = uncertain.publication.copy(stage = "file-sync"))),
            live.copy(snapshot = uncertain.copy(forceProvenance = "partial")),
            live.copy(artifactMetadata = artifactMetadata("partial")),
        )) {
            assertEquals(emptySet<Pcv3ResultAction>(), pcv3ResultActions(denied).actions)
        }
        val final = Pcv3Presentation.Final(uncertain, "uncertain-creation", 1, isCreation = true)
        assertEquals(setOf(Pcv3ResultAction.CLOSE_RESULT), pcv3ResultActions(final).actions)
    }

    @Test
    fun `PCV3 action projector accepts only exact live output and archive capabilities`() {
        val operation = mockk<Pcv3OperationCapability>(relaxed = true)
        val output = mockk<Pcv3OutputCapability>(relaxed = true)
        val archive = mockk<Pcv3ArchiveCapability>(relaxed = true)
        val durable = durablePublication()
        val degraded = Pcv3Presentation.Live(
            snapshot = snapshot(
                semantic = Pcv3Semantic(
                    "authenticated-degraded",
                    "metadata",
                    "PCV3_AUTHENTICATED_DEGRADED",
                ),
                publication = durable,
                forceProvenance = "verified",
                completionClass = "warning",
            ),
            operationId = "degraded",
            generation = 7,
            operationHandle = operation,
            consentHandle = null,
            archiveHandle = null,
            consent = null,
            outputHandle = output,
            outputPending = true,
        )
        val unverifiedMetadata = artifactMetadata("unverified-forensic")
        val unverified = degraded.copy(
            snapshot = snapshot(
                semantic = Pcv3Semantic(
                    "force-unverified",
                    "record-auth",
                    "PCV3_FORCE_UNVERIFIED",
                ),
                publication = durable,
                forceProvenance = "unverified",
                completionClass = "warning",
            ),
            artifactMetadata = unverifiedMetadata,
        )
        val recoveryActions = setOf(
            Pcv3ResultAction.SAVE_RECOVERY_ARTIFACT,
            Pcv3ResultAction.INSPECT_RECOVERY_ARTIFACT,
            Pcv3ResultAction.DISCARD_RECOVERY_ARTIFACT,
        )

        assertEquals(
            setOf(Pcv3ResultAction.SAVE_DECRYPTED_OUTPUT, Pcv3ResultAction.DISCARD_OUTPUT),
            pcv3ResultActions(degraded).actions,
        )
        assertEquals(recoveryActions, pcv3ResultActions(unverified).actions)

        listOf(
            "resource-busy",
            "resource-insufficient",
            "resource-unknown",
            "resource-limit",
            "PRIVATE diagnostic",
        ).forEach { diagnostic ->
            val contradictory = unverified.copy(
                snapshot = unverified.snapshot.copy(diagnostic = diagnostic),
            )
            assertEquals(
                "diagnostic=$diagnostic must deny Save, Inspect, and Discard",
                emptySet<Pcv3ResultAction>(),
                pcv3ResultActions(contradictory).actions,
            )
        }

        listOf(
            degraded.copy(
                snapshot = degraded.snapshot.copy(
                    semantic = Pcv3Semantic("success", "PRIVATE stage", "PCV3_SUCCESS"),
                    forceProvenance = "none",
                    completionClass = "clean",
                ),
            ),
            degraded.copy(
                snapshot = degraded.snapshot.copy(
                    semantic = degraded.snapshot.semantic.copy(stage = "none"),
                ),
            ),
            degraded.copy(
                snapshot = degraded.snapshot.copy(
                    semantic = degraded.snapshot.semantic.copy(stage = "record-auth"),
                ),
            ),
            unverified.copy(
                snapshot = unverified.snapshot.copy(
                    semantic = Pcv3Semantic(
                        "force-partial",
                        "credential-policy",
                        "PCV3_FORCE_PARTIAL",
                    ),
                    forceProvenance = "partial",
                ),
                artifactMetadata = artifactMetadata("partial"),
            ),
            unverified.copy(
                snapshot = unverified.snapshot.copy(
                    semantic = unverified.snapshot.semantic.copy(stage = "PRIVATE stage"),
                ),
            ),
            unverified.copy(outputHandle = null),
            unverified.copy(outputPending = false),
            unverified.copy(outputActionInFlight = true),
            unverified.copy(
                snapshot = unverified.snapshot.copy(forceProvenance = "verified"),
            ),
            unverified.copy(
                snapshot = unverified.snapshot.copy(
                    semantic = unverified.snapshot.semantic.copy(code = "PCV3_UNKNOWN"),
                ),
            ),
            unverified.copy(
                snapshot = unverified.snapshot.copy(
                    publication = durable.copy(stage = "file-sync"),
                ),
            ),
            unverified.copy(
                snapshot = unverified.snapshot.copy(restoredReceipt = "retained-receipt"),
            ),
            unverified.copy(artifactMetadata = unverifiedMetadata.copy(rangeCount = "3")),
        ).forEach { nearMiss ->
            assertEquals(emptySet<Pcv3ResultAction>(), pcv3ResultActions(nearMiss).actions)
        }

        val archivePending = degraded.copy(
            snapshot = snapshot(
                semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
                completionClass = "archive-pending",
                archivePending = true,
            ),
            archiveHandle = archive,
            outputHandle = null,
            outputPending = false,
        )
        assertEquals(
            Pcv3ResultActionProjection(
                setOf(Pcv3ResultAction.EXPORT_ARCHIVE, Pcv3ResultAction.CLOSE_ARCHIVE),
                R.string.pcv3_archive_close,
            ),
            pcv3ResultActions(archivePending),
        )
        assertEquals(
            emptySet<Pcv3ResultAction>(),
            pcv3ResultActions(archivePending.copy(archiveHandle = null)).actions,
        )
    }

    @Test
    fun `PCV3 page navigation uses canonical unsigned offsets without truncation or wrap`() {
        val metadata = artifactMetadata("partial").copy(
            rangeCount = "260",
            verifiedCount = "260",
            missingCount = "0",
        )
        val middlePage = Pcv3ArtifactPageView(
            offsetDecimal = "128",
            ranges = (128 until 256).map { index ->
                Pcv3ArtifactRangeView(
                    recordIndex = index.toString(),
                    start = (index * 2).toString(),
                    end = (index * 2 + 1).toString(),
                    status = "verified",
                )
            },
        )

        assertEquals(
            Pcv3ArtifactPageNavigation("0", "256"),
            pcv3ArtifactPageNavigation(metadata, middlePage),
        )
        assertEquals(
            Pcv3ArtifactPageNavigation(null, null),
            pcv3ArtifactPageNavigation(
                metadata.copy(
                    rangeCount = "0",
                    verifiedCount = "0",
                ),
                Pcv3ArtifactPageView("0", emptyList()),
            ),
        )

        val max = ULong.MAX_VALUE
        val wrappingPage = Pcv3ArtifactPageView(
            offsetDecimal = (max - 1uL).toString(),
            ranges = listOf(
                Pcv3ArtifactRangeView((max - 1uL).toString(), "0", "1", "verified"),
                Pcv3ArtifactRangeView(max.toString(), "2", "3", "verified"),
            ),
        )
        assertNull(
            pcv3ArtifactPageNavigation(
                metadata.copy(rangeCount = max.toString()),
                wrappingPage,
            ),
        )
        assertNull(
            pcv3ArtifactMetadataDisplay(
                metadata.copy(
                    rangeCount = max.toString(),
                    verifiedCount = max.toString(),
                    unverifiedCount = "1",
                ),
            ),
        )
    }

    private fun snapshot(
        statusCode: String = "none",
        statusArgs: List<String> = emptyList(),
        semantic: Pcv3Semantic = Pcv3Semantic("operation-failed", "input-io", "PCV3_OPERATION_FAILED"),
        publication: Pcv3Publication = Pcv3Publication(false, "none", "none", "none"),
        forceProvenance: String = "none",
        diagnostic: String = "none",
        completionClass: String = "unknown",
        warnings: List<String> = emptyList(),
        archivePending: Boolean = false,
        restoredReceipt: String = "",
        authenticatedComment: String = "",
    ) = Pcv3SnapshotView(
        statusCode = statusCode,
        statusArgs = statusArgs,
        semantic = semantic,
        publication = publication,
        forceProvenance = forceProvenance,
        d1BootstrapProvenance = "none",
        detailStage = "none",
        diagnostic = diagnostic,
        completionClass = completionClass,
        resultArgs = emptyList(),
        warnings = warnings,
        archivePending = archivePending,
        restoredReceipt = restoredReceipt,
        authenticatedComment = authenticatedComment,
    )

    private fun durablePublication() = Pcv3Publication(
        attempted = true,
        state = "published-durable",
        stage = "none",
        code = "PCV3_PUBLICATION_PUBLISHED_DURABLE",
    )

    private fun artifactMetadata(kind: String) = Pcv3ArtifactMetadataView(
        kind = kind,
        role = "none",
        plaintextLength = "17",
        finalStatus = "missing",
        rangeCount = "2",
        verifiedCount = "1",
        unverifiedCount = "0",
        missingCount = "1",
    )

    private companion object {
        private val staticStatusResources = linkedMapOf(
            "STARTING" to R.string.status_starting,
            "COMPLETED" to R.string.status_completed,
            "CANCELLED" to R.string.status_cancelled,
            "ERROR" to R.string.status_error,
            "COMPRESSING_FILES" to R.string.status_compressing_files,
            "GENERATING_VALUES" to R.string.status_generating_values,
            "DERIVING_KEY" to R.string.status_deriving_key,
            "READING_KEYFILES" to R.string.status_reading_keyfiles,
            "CALCULATING_VALUES" to R.string.status_calculating_values,
            "WRITING_VALUES" to R.string.status_writing_values,
            "SPLITTING" to R.string.status_splitting,
            "RECOMBINING_CHUNKS" to R.string.status_recombining_chunks,
            "READING_VALUES" to R.string.status_reading_values,
            "DUPLICATE_KEYFILES_WARNING" to R.string.status_duplicate_keyfiles_warning,
            "VERIFYING_INTEGRITY" to R.string.status_verifying_integrity,
            "MAC_VERIFICATION_FAILED_CONTINUING" to
                R.string.status_mac_verification_failed_continuing,
            "REPAIRING_VERIFYING" to R.string.status_repairing_verifying,
            "INTEGRITY_VERIFIED_DECRYPTING" to
                R.string.status_integrity_verified_decrypting,
            "COMPARING_VALUES" to R.string.status_comparing_values,
            "UNZIPPING" to R.string.status_unzipping,
            "ADDING_PLAUSIBLE_DENIABILITY" to
                R.string.status_adding_plausible_deniability,
            "REMOVING_DENIABILITY_PROTECTION" to
                R.string.status_removing_deniability_protection,
        )

        private val rateStatusResources = linkedMapOf(
            "COMPRESSING_RATE" to R.string.status_compressing_rate,
            "ENCRYPTING_RATE" to R.string.status_encrypting_rate,
            "SPLITTING_RATE" to R.string.status_splitting_rate,
            "RECOMBINING_RATE" to R.string.status_recombining_rate,
            "VERIFYING_RATE" to R.string.status_verifying_rate,
            "DECRYPTING_RATE" to R.string.status_decrypting_rate,
            "REPAIRING_RATE" to R.string.status_repairing_rate,
            "UNPACKING_RATE" to R.string.status_unpacking_rate,
            "ADDING_DENIABILITY_RATE" to R.string.status_adding_deniability_rate,
            "REMOVING_DENIABILITY_RATE" to R.string.status_removing_deniability_rate,
        )

        private val pcv3ProgressResources = linkedMapOf(
            Pcv3ProgressStatus.CHECKING_REQUEST to R.string.pcv3_progress_checking_request,
            Pcv3ProgressStatus.CHECKING_FACTORS to R.string.pcv3_progress_checking_factors,
            Pcv3ProgressStatus.CHECKING_RESOURCES to R.string.pcv3_progress_checking_resources,
            Pcv3ProgressStatus.DERIVING_KEY to R.string.pcv3_progress_deriving_key,
            Pcv3ProgressStatus.AUTHENTICATING to R.string.pcv3_progress_authenticating,
            Pcv3ProgressStatus.RECOVERING to R.string.pcv3_progress_recovering,
            Pcv3ProgressStatus.PREPARING_ARTIFACT to R.string.pcv3_progress_preparing_artifact,
            Pcv3ProgressStatus.PUBLISHING to R.string.pcv3_progress_publishing,
            Pcv3ProgressStatus.CONFIRMING_DURABILITY to
                R.string.pcv3_progress_confirming_durability,
        )

        private val resourceNotices = linkedMapOf(
            "resource-busy" to R.string.pcv3_resource_busy_title,
            "resource-insufficient" to R.string.pcv3_resource_insufficient_title,
            "resource-unknown" to R.string.pcv3_resource_unknown_title,
            "resource-limit" to R.string.pcv3_resource_limit_title,
        )
    }
}
