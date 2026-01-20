// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/util"
	"Picocrypt-NG/internal/volume"

	"fyne.io/fyne/v2"
)

// onClickStart handles the Start button click.
func (a *App) onClickStart() {
	// Validate
	if a.State.Mode == "" {
		return
	}

	hasCredentials := len(a.State.Keyfiles) > 0 || a.State.Password != ""
	if !hasCredentials {
		return
	}

	if a.State.Mode == "encrypt" && a.State.Password != a.State.CPassword {
		return
	}

	// Check if output exists (skip check for recursive mode - each file has different output)
	if _, err := os.Stat(a.State.OutputFile); err == nil && !a.State.Recursively {
		a.showOverwriteModal()
		return
	}

	a.startWork()
}

// startWork begins the encryption/decryption operation.
func (a *App) startWork() {
	a.State.ShowProgress = true
	a.State.FastDecode = true
	a.State.CanCancel = true
	a.State.ModalID++
	a.cancelled.Store(false)

	a.showProgressModal()

	if !a.State.Recursively {
		// Normal mode: process single file/folder(s)
		go func() {
			a.doWork()
			a.State.Working = false
			a.State.ShowProgress = false
			// Clean up mobile temp files after operation completes
			if isMobile() {
				a.CleanupMobileTempFiles()
			}
			fyne.Do(func() {
				if a.progressModal != nil {
					a.progressModal.Hide()
				}
				// Rebuild advanced section (clears options, resizes window for empty mode)
				a.updateAdvancedSection()
				a.updateUIState()
			})
		}()
	} else {
		// Recursive mode: process each file individually
		a.startRecursiveWork()
	}
}

// doWork performs the encryption or decryption operation.
// Returns true if the operation completed successfully.
func (a *App) doWork() bool {
	a.State.Working = true
	reporter := a.CreateReporter()

	if a.State.Mode == "encrypt" {
		return a.doEncrypt(reporter)
	}
	return a.doDecrypt(reporter)
}

// startRecursiveWork handles batch processing of multiple files individually.
func (a *App) startRecursiveWork() {
	if len(a.State.AllFiles) == 0 {
		a.State.MainStatus = "No files to process"
		a.State.MainStatusColor = util.YELLOW
		a.State.Working = false
		a.State.ShowProgress = false
		fyne.Do(func() {
			if a.progressModal != nil {
				a.progressModal.Hide()
			}
			a.updateUIState()
		})
		return
	}

	// Store all settings before they get cleared by onDrop/resetUI
	savedPassword := a.State.Password
	savedKeyfile := a.State.Keyfile
	savedKeyfiles := make([]string, len(a.State.Keyfiles))
	copy(savedKeyfiles, a.State.Keyfiles)
	savedKeyfileOrdered := a.State.KeyfileOrdered
	savedKeyfileLabel := a.State.KeyfileLabel
	savedComments := a.State.Comments
	savedParanoid := a.State.Paranoid
	savedReedSolomon := a.State.ReedSolomon
	savedDeniability := a.State.Deniability
	savedSplit := a.State.Split
	savedSplitSize := a.State.SplitSize
	savedSplitSelected := a.State.SplitSelected
	savedDelete := a.State.Delete

	files := make([]string, len(a.State.AllFiles))
	copy(files, a.State.AllFiles)

	go func() {
		var failedCount int
		var successCount int

		for i, file := range files {
			a.State.PopupStatus = fmt.Sprintf("Processing file %d/%d...", i+1, len(files))
			// Use binding - automatically updates bound widget
			_ = a.boundStatus.Set(a.State.PopupStatus)

			a.onDrop([]string{file})

			// Restore all saved settings
			a.State.Password = savedPassword
			a.State.CPassword = savedPassword
			a.State.Keyfile = savedKeyfile
			a.State.Keyfiles = make([]string, len(savedKeyfiles))
			copy(a.State.Keyfiles, savedKeyfiles)
			a.State.KeyfileOrdered = savedKeyfileOrdered
			a.State.KeyfileLabel = savedKeyfileLabel
			a.State.Comments = savedComments
			a.State.Paranoid = savedParanoid
			a.State.ReedSolomon = savedReedSolomon
			if a.State.Mode != "decrypt" {
				a.State.Deniability = savedDeniability
			}
			a.State.Split = savedSplit
			a.State.SplitSize = savedSplitSize
			a.State.SplitSelected = savedSplitSelected
			a.State.Delete = savedDelete

			if a.doWork() {
				successCount++
			} else {
				failedCount++
			}

			// Reset Working flag so next iteration's onDrop() isn't blocked
			// (onDrop has a guard to prevent race conditions during scanning/working)
			a.State.Working = false

			if a.cancelled.Load() {
				a.State.Working = false
				a.State.ShowProgress = false
				// Clean up mobile temp files after cancellation
				if isMobile() {
					a.CleanupMobileTempFiles()
				}
				fyne.Do(func() {
					if a.progressModal != nil {
						a.progressModal.Hide()
					}
					a.updateAdvancedSection()
					a.updateUIState()
				})
				return
			}
		}

		a.State.Working = false
		a.State.ShowProgress = false
		// Clean up mobile temp files after recursive operation completes
		if isMobile() {
			a.CleanupMobileTempFiles()
		}

		if failedCount == 0 {
			a.State.MainStatus = fmt.Sprintf("Completed (%d files)", successCount)
			a.State.MainStatusColor = util.GREEN
		} else if successCount == 0 {
			a.State.MainStatus = fmt.Sprintf("Failed (all %d files)", failedCount)
			a.State.MainStatusColor = util.RED
		} else {
			a.State.MainStatus = fmt.Sprintf("Completed (%d ok, %d failed)", successCount, failedCount)
			a.State.MainStatusColor = util.YELLOW
		}

		fyne.Do(func() {
			if a.progressModal != nil {
				a.progressModal.Hide()
			}
			a.updateAdvancedSection()
			a.updateUIState()
		})
	}()
}

// doEncrypt performs encryption using the volume package.
func (a *App) doEncrypt(reporter *app.UIReporter) bool {
	var chunkUnit fileops.SplitUnit
	switch a.State.SplitSelected {
	case 0:
		chunkUnit = fileops.SplitUnitKiB
	case 1:
		chunkUnit = fileops.SplitUnitMiB
	case 2:
		chunkUnit = fileops.SplitUnitGiB
	case 3:
		chunkUnit = fileops.SplitUnitTiB
	case 4:
		chunkUnit = fileops.SplitUnitTotal
	}

	chunkSize := 1
	if a.State.SplitSize != "" {
		n, err := strconv.Atoi(a.State.SplitSize)
		if err != nil || n <= 0 {
			a.State.MainStatus = "Invalid split size"
			a.State.MainStatusColor = util.RED
			return false
		}
		chunkSize = n
	}

	shouldDelete := a.State.Delete

	req := &volume.EncryptRequest{
		InputFile:      a.State.InputFile,
		InputFiles:     a.State.AllFiles,
		OnlyFolders:    a.State.OnlyFolders,
		OnlyFiles:      a.State.OnlyFiles,
		OutputFile:     a.State.OutputFile,
		Password:       a.State.Password,
		Keyfiles:       a.State.Keyfiles,
		KeyfileOrdered: a.State.KeyfileOrdered,
		Comments:       a.State.Comments,
		Paranoid:       a.State.Paranoid,
		ReedSolomon:    a.State.ReedSolomon,
		Deniability:    a.State.Deniability,
		Compress:       a.State.Compress,
		Split:          a.State.Split,
		ChunkSize:      chunkSize,
		ChunkUnit:      chunkUnit,
		Reporter:       reporter,
		RSCodecs:       a.rsCodecs,
	}

	filesToDelete := make([]string, len(a.State.AllFiles))
	copy(filesToDelete, a.State.AllFiles)
	foldersToDelete := make([]string, len(a.State.OnlyFolders))
	copy(foldersToDelete, a.State.OnlyFolders)
	inputFileToDelete := a.State.InputFile

	err := volume.Encrypt(context.Background(), req)
	if err != nil {
		if !a.cancelled.Load() {
			a.State.MainStatus = err.Error()
			a.State.MainStatusColor = util.RED
		}
		return false
	}

	a.State.ResetUI()
	a.State.MainStatus = "Completed"
	a.State.MainStatusColor = util.GREEN

	// Clear UI widgets to match the reset state
	fyne.Do(func() {
		if a.passwordEntry != nil {
			a.passwordEntry.SetText("")
		}
		if a.cPasswordEntry != nil {
			a.cPasswordEntry.SetText("")
		}
		if a.commentsEntry != nil {
			a.commentsEntry.SetText("")
		}
		a.updatePasswordStrength()
		a.updateValidation()
	})

	if shouldDelete {
		var deleteErrors []string
		if len(filesToDelete) > 0 {
			for _, f := range filesToDelete {
				if err := os.Remove(f); err != nil {
					deleteErrors = append(deleteErrors, f)
				}
			}
			for _, f := range foldersToDelete {
				if err := os.RemoveAll(f); err != nil {
					deleteErrors = append(deleteErrors, f)
				}
			}
		} else {
			if err := os.Remove(inputFileToDelete); err != nil {
				deleteErrors = append(deleteErrors, inputFileToDelete)
			}
		}
		if len(deleteErrors) > 0 {
			a.State.MainStatus = "Completed (some files couldn't be deleted)"
			a.State.MainStatusColor = util.YELLOW
		}
	}

	return true
}

// doDecrypt performs decryption using the volume package.
func (a *App) doDecrypt(reporter *app.UIReporter) bool {
	kept := false

	shouldDelete := a.State.Delete
	recombine := a.State.Recombine
	inputFile := a.State.InputFile

	req := &volume.DecryptRequest{
		InputFile:    a.State.InputFile,
		OutputFile:   a.State.OutputFile,
		Password:     a.State.Password,
		Keyfiles:     a.State.Keyfiles,
		ForceDecrypt: a.State.Keep,
		VerifyFirst:  a.State.VerifyFirst,
		AutoUnzip:    a.State.AutoUnzip,
		SameLevel:    a.State.SameLevel,
		Recombine:    a.State.Recombine,
		Deniability:  a.State.Deniability,
		Reporter:     reporter,
		RSCodecs:     a.rsCodecs,
		Kept:         &kept,
	}

	err := volume.Decrypt(context.Background(), req)
	if err != nil {
		if !a.cancelled.Load() {
			a.State.MainStatus = err.Error()
			a.State.MainStatusColor = util.RED
		}
		return false
	}

	a.State.ResetUI()

	// Clear UI widgets to match the reset state
	fyne.Do(func() {
		if a.passwordEntry != nil {
			a.passwordEntry.SetText("")
		}
		if a.cPasswordEntry != nil {
			a.cPasswordEntry.SetText("")
		}
		if a.commentsEntry != nil {
			a.commentsEntry.SetText("")
		}
		a.updatePasswordStrength()
		a.updateValidation()
	})

	if kept {
		a.State.Kept = true
		a.State.MainStatus = "The input file was modified. Please be careful"
		a.State.MainStatusColor = util.YELLOW
	} else {
		a.State.MainStatus = "Completed"
		a.State.MainStatusColor = util.GREEN
	}

	if shouldDelete && !kept {
		var deleteError bool
		if recombine {
			for i := 0; ; i++ {
				chunkPath := inputFile + "." + strconv.Itoa(i)
				if _, err := os.Stat(chunkPath); os.IsNotExist(err) {
					break
				}
				if err := os.Remove(chunkPath); err != nil {
					deleteError = true
				}
			}
		} else {
			if err := os.Remove(inputFile); err != nil {
				deleteError = true
			}
		}
		if deleteError {
			a.State.MainStatus = "Completed (volume couldn't be deleted)"
			a.State.MainStatusColor = util.YELLOW
		}
	}

	return true
}

// CreateReporter creates a UIReporter for progress updates.
func (a *App) CreateReporter() *app.UIReporter {
	return app.NewUIReporter(
		func(text string) {
			a.State.PopupStatus = text
			// Use binding - automatically thread-safe and updates bound widgets
			_ = a.boundStatus.Set(text)
		},
		func(fraction float32, info string) {
			a.State.Progress = fraction
			a.State.ProgressInfo = info
			// Use binding - automatically thread-safe and updates bound widget
			// Note: info (percentage string) not displayed separately - progress bar shows percentage
			_ = a.boundProgress.Set(float64(fraction))
		},
		func(can bool) {
			a.State.CanCancel = can
			fyne.Do(func() {
				if a.cancelButton != nil {
					if can {
						a.cancelButton.Enable()
					} else {
						a.cancelButton.Disable()
					}
				}
			})
		},
		func() {
			fyne.Do(func() {
				a.updateUIState()
			})
		},
		func() bool {
			return !a.State.Working
		},
	)
}
