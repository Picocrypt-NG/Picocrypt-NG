package io.github.picocrypt_ng.testutils

import android.content.Context
import android.net.Uri
import io.mockk.mockk

/**
 * Mock helpers for creating test doubles.
 */
object MockHelpers {
    
    /**
     * Creates a mock Context for unit tests.
     */
    fun createMockContext(): Context {
        return mockk<Context>(relaxed = true)
    }
    
    /**
     * Creates a mock Uri for file operations.
     */
    fun createMockUri(scheme: String = "content", path: String = "/test/file.txt"): Uri {
        return mockk<Uri>(relaxed = true) {
            // Mock basic URI behavior
        }
    }
}

