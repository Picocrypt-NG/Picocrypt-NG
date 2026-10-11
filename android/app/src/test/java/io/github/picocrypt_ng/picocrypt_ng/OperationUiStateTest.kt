package io.github.picocrypt_ng.picocrypt_ng

import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class OperationUiStateTest {
    @Test
    fun `forced unverified completion remains saveable without becoming clean success`() {
        val state = TestDataBuilders.createOperationState(
            type = OperationType.DECRYPT,
            status = OperationStatusData("COMPLETED_UNVERIFIED"),
            done = true,
            error = null,
        )

        val projected = state.toUiState()
        assertTrue("Recovery must retain the Save presentation", projected is OperationUiState.Success)
        assertEquals(OperationType.DECRYPT, (projected as OperationUiState.Success).type)
        assertNotEquals("Unverified output must not use clean-success copy",
            OperationUiState.Success(OperationType.DECRYPT), projected)
    }

    @Test
    fun `cancelled done operation maps to cancelled instead of success`() {
        val state = TestDataBuilders.createOperationState(
            type = OperationType.ENCRYPT,
            status = OperationStatusData(OperationStatus.CANCELLED),
            done = true,
            error = null
        )

        assertEquals(OperationUiState.Cancelled(OperationType.ENCRYPT), state.toUiState())
    }

    @Test
    fun `completed done operation still maps to success`() {
        val state = TestDataBuilders.createOperationState(
            type = OperationType.DECRYPT,
            status = OperationStatusData(OperationStatus.COMPLETED),
            done = true,
            error = null
        )

        assertEquals(OperationUiState.Success(OperationType.DECRYPT), state.toUiState())
    }

    @Test
    fun `done operation with error still maps to failed even if status says cancelled`() {
        val error = AppError.OperationError.GenericOperation("cancel failed")
        val state = TestDataBuilders.createOperationState(
            type = OperationType.DECRYPT,
            status = OperationStatusData(OperationStatus.CANCELLED),
            done = true,
            error = error
        )

        assertTrue(state.toUiState() is OperationUiState.Failed)
    }

    @Test
    fun `unknown terminal status maps to success`() {
        val state = TestDataBuilders.createOperationState(
            type = OperationType.DECRYPT,
            status = OperationStatusData(OperationStatus.UNKNOWN),
            done = true,
            error = null,
        )

        assertEquals(OperationUiState.Success(OperationType.DECRYPT), state.toUiState())
    }

    @Test
    fun `running UI state carries semantic status and detail`() {
        val status = OperationStatusData(
            code = OperationStatus.ENCRYPTING_RATE,
            speedMiBPerSecond = 12.34,
            eta = "01:02:03",
        )
        val detail = OperationProgressDetail(code = "ITEM_COUNT", current = 3, total = 10)
        val state = TestDataBuilders.createOperationState(
            type = OperationType.ENCRYPT,
            status = status,
            detail = detail,
            progress = 0.3f,
            done = false,
        )

        assertEquals(
            OperationUiState.Running(OperationType.ENCRYPT, 0.3f, status, detail),
            state.toUiState(),
        )
    }
}
