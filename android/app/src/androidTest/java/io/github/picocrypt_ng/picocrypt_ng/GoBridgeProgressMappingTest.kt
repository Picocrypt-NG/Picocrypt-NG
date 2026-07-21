package io.github.picocrypt_ng.picocrypt_ng

import androidx.test.ext.junit.runners.AndroidJUnit4
import mobile.ProgressResult as GoProgressResult
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class GoBridgeProgressMappingTest {
    @Test
    fun gomobileProgressAdapterMapsEveryConsumedNativeField() {
        val result = GoProgressResult().apply {
            setStatusCode("ENCRYPTING_RATE")
            setStatusSpeedMiBPerSecond(12.34)
            setStatusETA("01:02:03")
            setInfoCode("ITEM_COUNT")
            setInfoCurrent(3)
            setInfoTotal(10)
            setProgress(0.5f)
            setDone(true)
            setError("diagnostic only")
            setCode("GENERIC")
        }

        val progressState = with(GoBridge) { result.toProgressState() }

        assertEquals(
            ProgressState(
                status = OperationStatusData(
                    code = "ENCRYPTING_RATE",
                    speedMiBPerSecond = 12.34,
                    eta = "01:02:03",
                ),
                detail = OperationProgressDetail(
                    code = "ITEM_COUNT",
                    current = 3,
                    total = 10,
                ),
                progress = 0.5f,
                done = true,
                technicalError = "diagnostic only",
                errorCode = "GENERIC",
            ),
            progressState,
        )
    }
}
