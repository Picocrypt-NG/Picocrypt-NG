package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.content.res.Resources
import androidx.annotation.StringRes
import java.io.FileNotFoundException
import java.io.IOException
import java.util.Collections
import java.util.IdentityHashMap

fun AppError.localizedMessage(context: Context): String {
    val id = messageResId ?: return userMessage
    return if (messageArgs.isEmpty()) {
        context.getString(id)
    } else {
        context.getString(id, *messageArgs.toTypedArray())
    }
}

fun AppError.localizedMessage(resources: Resources): String {
    val id = messageResId ?: return userMessage
    return if (messageArgs.isEmpty()) {
        resources.getString(id)
    } else {
        resources.getString(id, *messageArgs.toTypedArray())
    }
}

@StringRes
fun failureReasonResId(error: Throwable): Int {
    val visited = Collections.newSetFromMap(IdentityHashMap<Throwable, Boolean>())
    var current: Throwable? = error
    while (current != null && visited.add(current)) {
        when (current) {
            is SecurityException -> return R.string.error_reason_permission_denied
            is FileNotFoundException -> return R.string.error_reason_file_not_found
            is AppError.FileError.InsufficientStorage -> {
                return R.string.error_reason_insufficient_storage
            }
            is IOException -> return R.string.error_reason_io
        }
        current = current.cause
    }
    return R.string.error_reason_unknown
}

fun localizedFailureReason(context: Context, error: Throwable): String =
    context.getString(failureReasonResId(error))

fun localizedFailureReason(resources: Resources, error: Throwable): String =
    resources.getString(failureReasonResId(error))
