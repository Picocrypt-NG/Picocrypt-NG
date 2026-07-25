package io.github.picocrypt_ng.picocrypt_ng

import java.io.File
import java.io.IOException
import mobile.Mobile

/**
 * Deletes an app-private tree without traversing symbolic links.
 *
 * Android delegates to Go's descriptor-relative os.Root implementation. The
 * JVM branch exists only for local unit tests, where the gomobile native
 * library cannot run.
 */
internal object NoFollowFileTree {
    private data class Entry(
        val isDirectory: Boolean,
        val identity: String,
    )

    private val isAndroidRuntime =
        System.getProperty("java.vm.name").equals("Dalvik", ignoreCase = true)

    fun delete(root: File, path: File): Boolean = try {
        if (isAndroidRuntime) {
            Mobile.removeTreeNoFollow(root.absolutePath, path.absolutePath).isEmpty()
        } else {
            deleteJvm(root, path)
        }
    } catch (_: Exception) {
        false
    }

    private fun deleteJvm(root: File, path: File): Boolean {
        val normalizedRoot = root.absoluteFile.normalize()
        val normalizedPath = path.absoluteFile.normalize()
        val relative = normalizedPath.relativeToOrNull(normalizedRoot) ?: return false
        if (relative.path.isEmpty()) {
            return false
        }

        var current = normalizedRoot
        relative.invariantSeparatorsPath.split('/').dropLast(1).forEach { component ->
            current = File(current, component)
            val entry = inspectJvm(current) ?: return true
            if (!entry.isDirectory || entry.identity.startsWith("link:")) {
                return false
            }
        }
        return deleteEntryJvm(normalizedPath)
    }

    private fun deleteEntryJvm(path: File): Boolean {
        val initial = inspectJvm(path) ?: return true
        if (!initial.isDirectory) {
            if (inspectJvm(path) != initial) {
                return false
            }
            removeJvm(path)
            return inspectJvm(path) == null
        }

        if (inspectJvm(path) != initial) {
            return false
        }
        val children = path.listFiles() ?: return false
        var allDeleted = true
        children.forEach { child ->
            if (!deleteEntryJvm(child)) {
                allDeleted = false
            }
        }
        if (!allDeleted) {
            return false
        }

        val completed = inspectJvm(path) ?: return true
        if (completed != initial || !completed.isDirectory) {
            return false
        }
        removeJvm(path)
        return inspectJvm(path) == null
    }

    private fun inspectJvm(path: File): Entry? {
        val absolute = path.absoluteFile
        val parent = absolute.parentFile
            ?: throw IOException("Cannot inspect a filesystem root")
        val names = parent.list() ?: throw IOException("Cannot list ${parent.absolutePath}")
        if (absolute.name !in names) {
            return null
        }

        val candidate = File(parent.canonicalFile, absolute.name)
        val canonical = candidate.canonicalFile
        val isLink = canonical != candidate.absoluteFile
        return Entry(
            isDirectory = !isLink && candidate.isDirectory,
            identity = if (isLink) {
                "link:${candidate.absolutePath}->${canonical.absolutePath}"
            } else {
                // JVM-only unit-test fallback. Android uses stable st_dev:st_ino.
                "path:${canonical.absolutePath}"
            },
        )
    }

    private fun removeJvm(path: File) {
        if (!path.delete()) {
            throw IOException("Cannot remove ${path.absolutePath}")
        }
    }
}
