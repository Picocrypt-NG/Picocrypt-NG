package io.github.picocrypt_ng.picocrypt_ng

import android.app.Application
import android.content.Context
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * ViewModel for managing form state and UI-related data.
 */
class MainViewModel(
    application: Application,
    private val savedStateHandle: SavedStateHandle
) : AndroidViewModel(application) {
    // Keys for SavedStateHandle (only for process recreation, not persistence)
    private val KEY_SELECTED_FILENAME = "selected_filename"
    private val KEY_COPIED_FILE_PATH = "copied_file_path"
    private val KEY_COMMENTS = "comments"
    
    // Restore saved state or use defaults (no persistence between app runs)
    private val initialFormData = FormData(
        selectedFilename = savedStateHandle.get<String>(KEY_SELECTED_FILENAME) ?: "",
        copiedFilePath = savedStateHandle.get<String>(KEY_COPIED_FILE_PATH) ?: "",
        comments = savedStateHandle.get<String>(KEY_COMMENTS) ?: "",
        passwordInput = CharArray(0), // Never save passwords - use empty CharArray
        confirmPasswordInput = CharArray(0), // Never save passwords - use empty CharArray
        reedSolomon = false, // Always default, no persistence
        paranoid = false, // Always default, no persistence
        deniability = false, // Always default, no persistence
        verifyFirst = false, // Always default, no persistence
        keyfileFilenames = emptyList(), // Always default, no persistence
        keyfileOrdered = false, // Always default, no persistence
        decryptionInfo = null // Never save decryption info (transient)
    )
    
    private val _formState = MutableStateFlow(initialFormData)
    
    val formState: StateFlow<FormData> = _formState.asStateFlow()
    
    // Error state for non-operation errors (file operations, etc.)
    private val _errorMessage = MutableStateFlow<AppError?>(null)
    val errorMessage: StateFlow<AppError?> = _errorMessage.asStateFlow()
    
    /**
     * Sets an error message to be displayed to the user.
     */
    fun setError(error: AppError) {
        _errorMessage.value = error
    }
    
    /**
     * Clears the current error message.
     */
    fun clearError() {
        _errorMessage.value = null
    }

    /** Retains the content-claimed normal PCV3 copy without entering a legacy route. */
    @Synchronized
    fun claimPcv3Normal(selectedFilename: String, ownedCopyPath: String): String? =
        retainPcv3Selection(selectedFilename, ownedCopyPath, refusedError = null)

    /** Retains bounded refusal metadata and returns every owned copy for immediate cleanup. */
    @Synchronized
    fun retainRefusedPcv3(
        selectedFilename: String,
        ownedCopyPath: String,
        error: AppError.OperationError.PCVUnavailable,
    ): List<String> {
        if (ownedCopyPath.isBlank()) return emptyList()
        val replaced = retainPcv3Selection(selectedFilename, ownedCopyPath, refusedError = error)
        val refused = _formState.value.pcv3OwnedSource?.release()
        return listOfNotNull(replaced, refused).distinct()
    }

    private fun retainPcv3Selection(
        selectedFilename: String,
        ownedCopyPath: String,
        refusedError: AppError.OperationError.PCVUnavailable?,
    ): String? {
        if (ownedCopyPath.isBlank()) {
            return null
        }
        val current = _formState.value
        current.clearPasswords()
        val releasedSource = current.pcv3OwnedSource?.release()
        val selected = current.copy(
            selectedFilename = selectedFilename,
            copiedFilePath = "",
            comments = "",
            passwordInput = CharArray(0),
            confirmPasswordInput = CharArray(0),
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            verifyFirst = false,
            keyfileFilenames = emptyList(),
            keyfileOrdered = false,
            compress = false,
            inputFiles = emptyList(),
            onlyFolders = emptyList(),
            onlyFiles = emptyList(),
            selectionKind = SelectionKind.SINGLE_FILE,
            suggestedOutputName = "",
            decryptionInfo = null,
            pcvUnavailable = refusedError != null,
            pcv3Intent = Pcv3OperationIntent(format = Pcv3FormatIntent.NORMAL),
            pcv3OwnedSource = Pcv3OwnedSource(ownedCopyPath),
        )

        clearSavedForm()
        _formState.value = selected
        _errorMessage.value = refusedError
        // Replacing an owner with the same deterministic app-private pathname is
        // an ownership handoff, not a request to delete the newly retained bytes.
        return releasedSource?.takeUnless { it == ownedCopyPath }
    }

    /** Moves one already-copied regular legacy candidate into explicit D1 intent. */
    @Synchronized
    fun selectPcv3D1(): Boolean {
        val current = _formState.value
        if (current.isPcv3Selection || current.pcvUnavailable ||
            current.selectionKind != SelectionKind.SINGLE_FILE ||
            current.copiedFilePath.isBlank() || current.inputFiles.isNotEmpty() ||
            current.hasAnyCredentialInput
        ) {
            return false
        }
        _formState.value = current.copy(
            copiedFilePath = "",
            comments = "",
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            verifyFirst = false,
            keyfileOrdered = false,
            compress = false,
            suggestedOutputName = "",
            decryptionInfo = null,
            pcv3Intent = Pcv3OperationIntent(format = Pcv3FormatIntent.D1),
            pcv3OwnedSource = Pcv3OwnedSource(current.copiedFilePath),
        )
        clearSavedForm()
        _errorMessage.value = null
        return true
    }

    @Synchronized
    fun setPcv3Action(action: Pcv3ActionIntent) {
        updatePcv3Intent { it.copy(action = action) }
    }

    @Synchronized
    fun setPcv3FactorPolicy(policy: Pcv3FactorPolicyIntent) {
        updatePcv3Intent { current ->
            val currentUsesKeyfiles = current.factorPolicy == Pcv3FactorPolicyIntent.KEYFILES_ONLY ||
                current.factorPolicy == Pcv3FactorPolicyIntent.PASSWORD_AND_KEYFILES
            val nextUsesKeyfiles = policy == Pcv3FactorPolicyIntent.KEYFILES_ONLY ||
                policy == Pcv3FactorPolicyIntent.PASSWORD_AND_KEYFILES
            current.copy(
                factorPolicy = policy,
                keyfileOrder = if (currentUsesKeyfiles && nextUsesKeyfiles) current.keyfileOrder else null,
            )
        }
    }

    @Synchronized
    fun setPcv3KeyfileOrder(order: Pcv3KeyfileOrderIntent?) {
        updatePcv3Intent { current ->
            if (current.factorPolicy == Pcv3FactorPolicyIntent.PASSWORD_ONLY) current
            else current.copy(keyfileOrder = order)
        }
    }

    private inline fun updatePcv3Intent(transform: (Pcv3OperationIntent) -> Pcv3OperationIntent) {
        val current = _formState.value
        val intent = current.pcv3Intent ?: return
        if (current.pcvUnavailable || current.pcv3OwnedSource?.isAvailable() != true) return
        _formState.value = current.copy(pcv3Intent = transform(intent))
        clearSavedForm()
    }

    /**
     * Atomically validates and transfers one strict PCV3 request. The source path
     * crosses Kotlin only inside [Pcv3Request], and the original mutable password
     * buffer becomes the caller's owner. A stale second take always returns null.
     */
    @Synchronized
    fun takePcv3Operation(target: String): Pcv3OperationTransfer? {
        val current = _formState.value
        val intent = current.pcv3Intent ?: return null
        val mode = intent.goModeOrNull() ?: return null
        val factorPolicy = intent.factorPolicyCodeOrNull() ?: return null
        val keyfileOrder = intent.keyfileOrderCodeOrNull() ?: return null
        if (target.isBlank() || !current.isFormValid) return null
        val source = current.pcv3OwnedSource?.take() ?: return null

        val password = current.passwordInput
        current.confirmPasswordInput.fill('\u0000')
        val transfer = Pcv3OperationTransfer(
            intent = intent,
            request = Pcv3Request(
                mode = mode,
                factorPolicy = factorPolicy,
                keyfileOrder = keyfileOrder,
                source = source,
                target = target,
                keyfiles = current.keyfileFilenames.map(KeyfileInfo::internalPath),
            ),
            password = password,
        )

        _formState.value = current.copy(
            selectedFilename = "",
            copiedFilePath = "",
            comments = "",
            passwordInput = CharArray(0),
            confirmPasswordInput = CharArray(0),
            keyfileFilenames = emptyList(),
            inputFiles = emptyList(),
            onlyFolders = emptyList(),
            onlyFiles = emptyList(),
            suggestedOutputName = "",
            decryptionInfo = null,
            pcvUnavailable = false,
            pcv3Intent = null,
            pcv3OwnedSource = null,
        )
        clearSavedForm()
        _errorMessage.value = null
        return transfer
    }
    
    /**
     * Atomically validates and transfers one strict PCV3 creation request built from
     * the legacy-shaped encrypt form. Ownership of the copied source and password
     * buffer moves to the caller exactly as in [takePcv3Operation].
     */
    @Synchronized
    fun takePcv3CreateOperation(target: String): Pcv3OperationTransfer? {
        val current = _formState.value
        if (!current.isPcv3Creation || target.isBlank() || !current.isFormValid) return null
        val factorPolicy = when {
            current.hasPassword && current.hasKeyfiles -> Pcv3FactorPolicyIntent.PASSWORD_AND_KEYFILES
            current.hasPassword -> Pcv3FactorPolicyIntent.PASSWORD_ONLY
            current.hasKeyfiles -> Pcv3FactorPolicyIntent.KEYFILES_ONLY
            else -> return null
        }
        val keyfileOrder = when (factorPolicy) {
            Pcv3FactorPolicyIntent.PASSWORD_ONLY -> null
            Pcv3FactorPolicyIntent.KEYFILES_ONLY,
            Pcv3FactorPolicyIntent.PASSWORD_AND_KEYFILES,
            -> if (current.keyfileOrdered) Pcv3KeyfileOrderIntent.SELECTED else Pcv3KeyfileOrderIntent.ANY
        }
        val intent = Pcv3OperationIntent(
            format = if (current.deniability) Pcv3FormatIntent.D1 else Pcv3FormatIntent.NORMAL,
            action = Pcv3ActionIntent.CREATE,
            factorPolicy = factorPolicy,
            keyfileOrder = keyfileOrder,
        )
        val mode = intent.goModeOrNull() ?: return null
        val factorPolicyCode = intent.factorPolicyCodeOrNull() ?: return null
        val keyfileOrderCode = intent.keyfileOrderCodeOrNull() ?: return null

        // A D1 volume carries no plaintext comment, including stale form values.
        val request = Pcv3WriteRequest(
            mode = mode,
            factorPolicy = factorPolicyCode,
            keyfileOrder = keyfileOrderCode,
            source = current.copiedFilePath.ifEmpty { current.inputFiles.firstOrNull() ?: return null },
            target = target,
            keyfiles = current.keyfileFilenames.map(KeyfileInfo::internalPath),
            comment = if (current.deniability) "" else current.comments,
            suite = if (current.paranoid || current.deniability) "paranoid" else "standard",
            payloadRS = current.reedSolomon,
            inputFiles = current.inputFiles, onlyFiles = current.onlyFiles, onlyFolders = current.onlyFolders, compress = current.compress,
        )
        // Refuse before clearing either credential buffer or transferring staged paths.
        if (GoBridge.buildPcv3WriteRequestJson(request) == null) {
            _errorMessage.value = AppError.OperationError.GenericOperation(
                userMessage = "",
                technicalMessage = "PCV3_BRIDGE_INVALID_REQUEST",
                messageResId = R.string.pcv3_request_too_large,
            )
            return null
        }
        val password = current.passwordInput
        current.confirmPasswordInput.fill('\u0000')
        val transfer = Pcv3OperationTransfer(
            intent = intent,
            request = request,
            password = password,
            createName = if (current.deniability) {
                current.selectedFilename
            } else {
                current.suggestedOutputNameFor(OperationType.ENCRYPT)
            },
        )

        _formState.value = current.copy(
            selectedFilename = "",
            copiedFilePath = "",
            comments = "",
            passwordInput = CharArray(0),
            confirmPasswordInput = CharArray(0),
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            keyfileFilenames = emptyList(),
            keyfileOrdered = false,
            compress = false,
            inputFiles = emptyList(),
            onlyFiles = emptyList(),
            onlyFolders = emptyList(),
            selectionKind = SelectionKind.SINGLE_FILE,
            suggestedOutputName = "",
            decryptionInfo = null,
        )
        clearSavedForm()
        _errorMessage.value = null
        return transfer
    }

    /**
     * Updates the form data with new values.
     * Only saves minimal fields to SavedStateHandle for process recreation.
     * Advanced settings and keyfile settings are NOT persisted.
     */
    @Synchronized
    fun updateFormData(newData: FormData) {
        val current = _formState.value
        if (current.isPcv3Selection) {
            // Generic UI copies are needed only for the existing keyfile picker. Route,
            // format, action, factor policy, refusal, and source ownership stay behind
            // their explicit transitions and cannot be changed by a stale FormData copy.
            if (current.pcvUnavailable || newData.pcv3OwnedSource !== current.pcv3OwnedSource) {
                return
            }
            _formState.value = current.copy(keyfileFilenames = newData.keyfileFilenames)
            clearSavedForm()
            return
        }
        // A generic legacy update cannot mint a claimed/refused PCV3 route.
        if (newData.pcv3Intent != null || newData.pcv3OwnedSource != null || newData.pcvUnavailable) {
            return
        }
        _formState.value = newData
        persistFormData(newData)
        // Note: passwordInput, confirmPasswordInput, decryptionInfo, advanced settings, 
        // and keyfile settings are NOT saved
    }
    
    /**
     * Updates password fields atomically to prevent race conditions.
     * Uses StateFlow.update() to ensure thread-safe updates.
     * 
     * @param password New password as CharArray, or null to keep current
     * @param confirmPassword New confirm password as CharArray, or null to keep current
     */
    @Synchronized
    fun updatePasswords(password: CharArray? = null, confirmPassword: CharArray? = null) {
        if (_formState.value.isPcv3Selection && _formState.value.pcvUnavailable) {
            password?.fill('\u0000')
            confirmPassword?.fill('\u0000')
            return
        }
        _formState.update { current ->
            // Store references to old password arrays for clearing
            val oldPassword = current.passwordInput
            val oldConfirm = current.confirmPasswordInput
            
            // Create new FormData with updated passwords (using copyOf to create new arrays)
            val updated = current.copy(
                passwordInput = password?.copyOf() ?: current.passwordInput,
                confirmPasswordInput = confirmPassword?.copyOf() ?: current.confirmPasswordInput
            )
            
            // Clear old password arrays if they're being replaced
            // We clear the old arrays since we've created new copies
            if (password != null) {
                oldPassword.fill('\u0000')
            }
            if (confirmPassword != null) {
                oldConfirm.fill('\u0000')
            }
            
            updated
        }
        
        // Update SavedStateHandle (passwords are not saved, but other fields might have changed)
        persistFormData(_formState.value)
    }
    
    /**
     * Clears sensitive fields from FormData while preserving convenience settings.
     * Explicitly zeros password arrays for security.
     * @param clearFiles If true, also clears file selections and keyfiles
     */
    @Synchronized
    fun clearSensitiveData(clearFiles: Boolean = true): String? {
        val current = _formState.value
        val releasedSource = if (clearFiles) current.pcv3OwnedSource?.release() else null
        
        // Clear and zero password arrays
        current.clearPasswords()
        
        // Always clear passwords (create new empty arrays)
        var cleared = current.copy(
            passwordInput = CharArray(0),
            confirmPasswordInput = CharArray(0)
        )
        
        // Conditionally clear files
        if (clearFiles) {
            cleared = cleared.copy(
                selectedFilename = "",
                copiedFilePath = "",
                comments = "",
                keyfileFilenames = emptyList(),
                inputFiles = emptyList(),
                onlyFolders = emptyList(),
                onlyFiles = emptyList(),
                selectionKind = SelectionKind.SINGLE_FILE,
                suggestedOutputName = "",
                decryptionInfo = null,
                pcvUnavailable = false,
                pcv3Intent = null,
                pcv3OwnedSource = null,
            )
        }
        
        _formState.value = cleared
        persistFormData(cleared)
        return releasedSource
    }
    
    /**
     * Resets the form to default values. Used when a new file is selected.
     * Clears all fields including comments, passwords, advanced settings, and keyfiles.
     * Explicitly zeros password arrays for security.
     */
    @Synchronized
    fun resetFormToDefaults(): List<String> {
        val current = _formState.value
        val releasedSources = buildList {
            current.copiedFilePath.takeIf(String::isNotBlank)?.let(::add)
            current.pcv3OwnedSource?.release()?.let(::add)
        }.distinct()
        
        // Clear and zero existing password arrays
        current.clearPasswords()
        
        val reset = current.copy(
            selectedFilename = "",
            copiedFilePath = "",
            comments = "",
            passwordInput = CharArray(0),
            confirmPasswordInput = CharArray(0),
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            verifyFirst = false,
            keyfileFilenames = emptyList(),
            keyfileOrdered = false,
            inputFiles = emptyList(),
            onlyFolders = emptyList(),
            onlyFiles = emptyList(),
            selectionKind = SelectionKind.SINGLE_FILE,
            suggestedOutputName = "",
            decryptionInfo = null,
            pcvUnavailable = false,
            pcv3Intent = null,
            pcv3OwnedSource = null,
        )
        _formState.value = reset
        persistFormData(reset)
        return releasedSources
    }

    private fun persistFormData(data: FormData) {
        if (data.isPcv3Selection || data.pcvUnavailable) {
            clearSavedForm()
            return
        }
        // Only convenience fields survive process recreation. Intent, credentials,
        // keyfiles, source ownership, and advanced options never do.
        savedStateHandle[KEY_SELECTED_FILENAME] = data.selectedFilename
        savedStateHandle[KEY_COPIED_FILE_PATH] = data.copiedFilePath
        savedStateHandle[KEY_COMMENTS] = data.comments
    }

    private fun clearSavedForm() {
        savedStateHandle.remove<String>(KEY_SELECTED_FILENAME)
        savedStateHandle.remove<String>(KEY_COPIED_FILE_PATH)
        savedStateHandle.remove<String>(KEY_COMMENTS)
    }
}
