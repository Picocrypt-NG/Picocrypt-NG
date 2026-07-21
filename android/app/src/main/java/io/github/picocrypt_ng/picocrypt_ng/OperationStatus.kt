package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import androidx.annotation.StringRes

data class OperationStatusData(
    val code: String,
    val speedMiBPerSecond: Double = 0.0,
    val eta: String = "",
)

data class OperationProgressDetail(
    val code: String,
    val current: Long = 0,
    val total: Long = 0,
)

data class OperationDisplayText(
    val status: String,
    val detail: String? = null,
)

object OperationStatus {
    const val STARTING = "STARTING"
    const val COMPLETED = "COMPLETED"
    const val CANCELLED = "CANCELLED"
    const val ERROR = "ERROR"
    const val COMPRESSING_FILES = "COMPRESSING_FILES"
    const val GENERATING_VALUES = "GENERATING_VALUES"
    const val DERIVING_KEY = "DERIVING_KEY"
    const val READING_KEYFILES = "READING_KEYFILES"
    const val CALCULATING_VALUES = "CALCULATING_VALUES"
    const val WRITING_VALUES = "WRITING_VALUES"
    const val SPLITTING = "SPLITTING"
    const val RECOMBINING_CHUNKS = "RECOMBINING_CHUNKS"
    const val READING_VALUES = "READING_VALUES"
    const val DUPLICATE_KEYFILES_WARNING = "DUPLICATE_KEYFILES_WARNING"
    const val VERIFYING_INTEGRITY = "VERIFYING_INTEGRITY"
    const val MAC_VERIFICATION_FAILED_CONTINUING = "MAC_VERIFICATION_FAILED_CONTINUING"
    const val REPAIRING_VERIFYING = "REPAIRING_VERIFYING"
    const val INTEGRITY_VERIFIED_DECRYPTING = "INTEGRITY_VERIFIED_DECRYPTING"
    const val COMPARING_VALUES = "COMPARING_VALUES"
    const val UNZIPPING = "UNZIPPING"
    const val ADDING_PLAUSIBLE_DENIABILITY = "ADDING_PLAUSIBLE_DENIABILITY"
    const val REMOVING_DENIABILITY_PROTECTION = "REMOVING_DENIABILITY_PROTECTION"
    const val COMPRESSING_RATE = "COMPRESSING_RATE"
    const val ENCRYPTING_RATE = "ENCRYPTING_RATE"
    const val SPLITTING_RATE = "SPLITTING_RATE"
    const val RECOMBINING_RATE = "RECOMBINING_RATE"
    const val VERIFYING_RATE = "VERIFYING_RATE"
    const val DECRYPTING_RATE = "DECRYPTING_RATE"
    const val REPAIRING_RATE = "REPAIRING_RATE"
    const val UNPACKING_RATE = "UNPACKING_RATE"
    const val ADDING_DENIABILITY_RATE = "ADDING_DENIABILITY_RATE"
    const val REMOVING_DENIABILITY_RATE = "REMOVING_DENIABILITY_RATE"
    const val UNKNOWN = "UNKNOWN"
    const val WORKING = UNKNOWN
}

object OperationProgress {
    const val NONE = "NONE"
    const val PERCENT = "PERCENT"
    const val ITEM_COUNT = "ITEM_COUNT"
    const val UNKNOWN = "UNKNOWN"
}

fun renderOperationStatus(
    context: Context,
    status: OperationStatusData,
    detail: OperationProgressDetail,
    progress: Float,
): OperationDisplayText {
    val statusText = staticStatusResource(status.code)?.let(context::getString)
        ?: rateStatusResource(status.code)?.let { resourceId ->
            if (status.speedMiBPerSecond.isFinite() &&
                status.speedMiBPerSecond >= 0.0 &&
                validEta.matches(status.eta)
            ) {
                context.getString(resourceId, status.speedMiBPerSecond, status.eta)
            } else {
                null
            }
        }
        ?: context.getString(R.string.fgs_working)

    val detailText = when (detail.code) {
        OperationProgress.PERCENT -> {
            if (progress.isFinite() && progress in 0f..1f) {
                context.getString(R.string.progress_percent, progress.toDouble() * 100.0)
            } else {
                null
            }
        }
        OperationProgress.ITEM_COUNT -> {
            if (detail.current >= 0 &&
                detail.total > 0 &&
                detail.current <= detail.total &&
                detail.total <= Int.MAX_VALUE
            ) {
                context.resources.getQuantityString(
                    R.plurals.progress_item_count,
                    detail.total.toInt(),
                    detail.current,
                    detail.total,
                )
            } else {
                null
            }
        }
        else -> null
    }

    return OperationDisplayText(statusText, detailText)
}

@StringRes
private fun staticStatusResource(code: String): Int? = when (code) {
    OperationStatus.STARTING -> R.string.status_starting
    OperationStatus.COMPLETED -> R.string.status_completed
    OperationStatus.CANCELLED -> R.string.status_cancelled
    OperationStatus.ERROR -> R.string.status_error
    OperationStatus.COMPRESSING_FILES -> R.string.status_compressing_files
    OperationStatus.GENERATING_VALUES -> R.string.status_generating_values
    OperationStatus.DERIVING_KEY -> R.string.status_deriving_key
    OperationStatus.READING_KEYFILES -> R.string.status_reading_keyfiles
    OperationStatus.CALCULATING_VALUES -> R.string.status_calculating_values
    OperationStatus.WRITING_VALUES -> R.string.status_writing_values
    OperationStatus.SPLITTING -> R.string.status_splitting
    OperationStatus.RECOMBINING_CHUNKS -> R.string.status_recombining_chunks
    OperationStatus.READING_VALUES -> R.string.status_reading_values
    OperationStatus.DUPLICATE_KEYFILES_WARNING -> R.string.status_duplicate_keyfiles_warning
    OperationStatus.VERIFYING_INTEGRITY -> R.string.status_verifying_integrity
    OperationStatus.MAC_VERIFICATION_FAILED_CONTINUING ->
        R.string.status_mac_verification_failed_continuing
    OperationStatus.REPAIRING_VERIFYING -> R.string.status_repairing_verifying
    OperationStatus.INTEGRITY_VERIFIED_DECRYPTING ->
        R.string.status_integrity_verified_decrypting
    OperationStatus.COMPARING_VALUES -> R.string.status_comparing_values
    OperationStatus.UNZIPPING -> R.string.status_unzipping
    OperationStatus.ADDING_PLAUSIBLE_DENIABILITY -> R.string.status_adding_plausible_deniability
    OperationStatus.REMOVING_DENIABILITY_PROTECTION ->
        R.string.status_removing_deniability_protection
    else -> null
}

@StringRes
private fun rateStatusResource(code: String): Int? = when (code) {
    OperationStatus.COMPRESSING_RATE -> R.string.status_compressing_rate
    OperationStatus.ENCRYPTING_RATE -> R.string.status_encrypting_rate
    OperationStatus.SPLITTING_RATE -> R.string.status_splitting_rate
    OperationStatus.RECOMBINING_RATE -> R.string.status_recombining_rate
    OperationStatus.VERIFYING_RATE -> R.string.status_verifying_rate
    OperationStatus.DECRYPTING_RATE -> R.string.status_decrypting_rate
    OperationStatus.REPAIRING_RATE -> R.string.status_repairing_rate
    OperationStatus.UNPACKING_RATE -> R.string.status_unpacking_rate
    OperationStatus.ADDING_DENIABILITY_RATE -> R.string.status_adding_deniability_rate
    OperationStatus.REMOVING_DENIABILITY_RATE -> R.string.status_removing_deniability_rate
    else -> null
}

private val validEta = Regex("^[0-9]{2,}:[0-5][0-9]:[0-5][0-9]$")
