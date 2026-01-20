package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/util"
	"Picocrypt-NG/internal/volume"

	"fyne.io/fyne/v2"
)

// onDrop handles files and folders dropped onto the window (matches original exactly).
func (a *App) onDrop(names []string) {
	// If keyfile modal is open, handle as keyfiles
	if a.State.ShowKeyfile {
		a.handleKeyfileDrop(names)
		return
	}

	// Prevent race condition: ignore new drops while scanning or working
	// This prevents multiple goroutines from simultaneously modifying AllFiles
	if a.State.Scanning || a.State.Working {
		return
	}

	a.State.Scanning = true
	a.State.CompressDone = 0
	a.State.CompressTotal = 0
	// Reset UI synchronously - onDrop runs on UI thread, so fyne.Do() is not needed
	// Using fyne.Do() here would cause a race condition where Mode gets cleared
	// AFTER it's set below, because fyne.Do() queues the call for later execution
	a.resetUI()

	// One item dropped
	if len(names) == 1 {
		stat, err := os.Stat(names[0])
		if err != nil {
			a.State.MainStatus = "Failed to stat dropped item"
			a.State.MainStatusColor = util.RED
			a.State.Scanning = false
			fyne.Do(func() {
				a.refreshUI()
			})
			return
		}

		// A folder was dropped
		if stat.IsDir() {
			a.State.Mode = "encrypt"
			a.State.InputLabel = "1 folder"
			a.State.StartLabel = "Zip and Encrypt"
			a.State.OnlyFolders = append(a.State.OnlyFolders, names[0])
			a.State.InputFile = filepath.Join(filepath.Dir(names[0]),
				"encrypted-"+strconv.Itoa(int(time.Now().Unix()))) + ".zip"
			a.State.OutputFile = a.State.InputFile + ".pcv"
		} else {
			// A file was dropped
			a.State.RequiredFreeSpace = stat.Size()

			// Is the file a part of a split volume?
			endsNum := false
			for _, c := range "0123456789" {
				if strings.HasSuffix(names[0], string(c)) {
					endsNum = true
					break
				}
			}
			isSplit := strings.Contains(names[0], ".pcv.") && endsNum

			// Decide if encrypting or decrypting
			if strings.HasSuffix(names[0], ".pcv") || isSplit {
				a.handleDecryptDrop(names[0], isSplit)
				// For decrypt, no folder scanning needed
				a.State.Scanning = false
				fyne.Do(func() {
					a.refreshUI()
					a.refreshAdvanced()
				})
				return
			} else {
				// Encrypting a single file
				a.State.Mode = "encrypt"
				a.State.InputFile = names[0]
				a.State.InputLabel = "1 file"
				a.State.StartLabel = "Encrypt"
				// Set output file based on compress state
				if a.State.Compress {
					a.State.OutputFile = names[0] + ".zip.pcv"
				} else {
					a.State.OutputFile = names[0] + ".pcv"
				}
				a.State.OnlyFiles = append(a.State.OnlyFiles, names[0])
				a.State.AllFiles = append(a.State.AllFiles, names[0])
				// Add to compressTotal for size display (like original line 1077)
				a.State.CompressTotal += stat.Size()
			}
		}
	} else {
		// Multiple items dropped - always encrypt
		a.handleMultipleDrop(names)
	}

	// Recursively add all files in 'onlyFolders' to 'allFiles' (matches original lines 1133-1173)
	go func() {
		oldInputLabel := a.State.InputLabel
		for _, name := range a.State.OnlyFolders {
			if filepath.Walk(name, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					fyne.Do(func() {
						a.resetUI()
						a.State.MainStatus = "Failed to walk through dropped items"
						a.State.MainStatusColor = util.RED
						a.refreshUI()
					})
					return err
				}
				stat, err := os.Stat(path)
				if err != nil {
					fyne.Do(func() {
						a.resetUI()
						a.State.MainStatus = "Failed to walk through dropped items"
						a.State.MainStatusColor = util.RED
						a.refreshUI()
					})
					return err
				}
				// If 'path' is a valid file path, add to 'allFiles'
				if !stat.IsDir() {
					fileSize := stat.Size()
					fyne.Do(func() {
						a.State.AllFiles = append(a.State.AllFiles, path)
						a.State.CompressTotal += fileSize
						a.State.RequiredFreeSpace += fileSize
						a.State.InputLabel = fmt.Sprintf("Scanning files... (%s)", util.Sizeify(a.State.CompressTotal))
						a.refreshUI()
					})
				}
				return nil
			}) != nil {
				fyne.Do(func() {
					a.resetUI()
					a.State.MainStatus = "Failed to walk through dropped items"
					a.State.MainStatusColor = util.RED
					a.refreshUI()
				})
				return
			}
		}
		fyne.Do(func() {
			a.State.InputLabel = fmt.Sprintf("%s (%s)", oldInputLabel, util.Sizeify(a.State.CompressTotal))
			a.State.Scanning = false
			a.refreshUI()
			a.refreshAdvanced()
		})
	}()
}

// handleDecryptDrop handles a .pcv file being dropped for decryption.
func (a *App) handleDecryptDrop(name string, isSplit bool) {
	a.State.Mode = "decrypt"
	a.State.InputLabel = "Volume for decryption"
	a.State.StartLabel = "Decrypt"
	a.State.CommentsLabel = "Comments (read-only):"
	a.State.CommentsDisabled = true

	// Add the file to onlyFiles (required for UI enable/disable logic)
	a.State.OnlyFiles = append(a.State.OnlyFiles, name)

	// Get the correct input and output filenames
	if isSplit {
		ind := strings.Index(name, ".pcv")
		name = name[:ind+4]
		a.State.InputFile = name
		a.State.OutputFile = name[:ind]
		a.State.Recombine = true

		// Find out the number of split chunks
		totalFiles := 0
		for {
			stat, err := os.Stat(fmt.Sprintf("%s.%d", a.State.InputFile, totalFiles))
			if err != nil {
				break
			}
			totalFiles++
			a.State.CompressTotal += stat.Size()
		}
		a.State.RequiredFreeSpace = a.State.CompressTotal
	} else {
		a.State.InputFile = name
		a.State.OutputFile = name[:len(name)-4]
	}

	// Open the input file in read-only mode
	var fin *os.File
	var err error
	if isSplit {
		fin, err = os.Open(name + ".0")
	} else {
		fin, err = os.Open(name)
	}
	if err != nil {
		a.State.MainStatus = "Read access denied"
		a.State.MainStatusColor = util.RED
		fyne.Do(func() {
			a.resetUI()
			a.refreshUI()
		})
		return
	}
	defer func() { _ = fin.Close() }()

	// Check if version can be read from header
	tmp := make([]byte, 15)
	if n, err := fin.Read(tmp); err != nil || n != 15 {
		a.State.MainStatus = "Failed to read header"
		a.State.MainStatusColor = util.RED
		return
	}

	tmp, err = encoding.Decode(a.rsCodecs.RS5, tmp, false)
	if valid, _ := regexp.Match(`^v\d\.\d{2}`, tmp); err != nil || !valid {
		// Volume has plausible deniability
		a.State.Deniability = true
		a.State.MainStatus = "Cannot read header, volume may be deniable"
		return
	}

	// Read comments from file
	tmp = make([]byte, 15)
	if n, err := fin.Read(tmp); err != nil || n != 15 {
		a.State.MainStatus = "Failed to read header"
		a.State.MainStatusColor = util.RED
		return
	}

	tmp, err = encoding.Decode(a.rsCodecs.RS5, tmp, false)
	if err == nil {
		commentsLength, err := strconv.Atoi(string(tmp))
		if err != nil {
			a.State.Comments = "Comment length is corrupted"
		} else {
			tmp = make([]byte, commentsLength*3)
			if n, err := fin.Read(tmp); err != nil || n != commentsLength*3 {
				a.State.MainStatus = "Failed to read comments"
				a.State.MainStatusColor = util.RED
				return
			}
			a.State.Comments = ""
			for i := 0; i < commentsLength*3; i += 3 {
				t, err := encoding.Decode(a.rsCodecs.RS1, tmp[i:i+3], false)
				if err != nil {
					a.State.Comments = "Comments are corrupted"
					break
				}
				a.State.Comments += string(t)
			}
		}
	} else {
		a.State.Comments = "Comments are corrupted"
	}

	// Update comments entry if it exists
	fyne.Do(func() {
		if a.commentsEntry != nil {
			a.commentsEntry.SetText(a.State.Comments)
		}
	})

	// Read flags from file
	flags := make([]byte, 15)
	if n, err := fin.Read(flags); err != nil || n != 15 {
		a.State.MainStatus = "Failed to read header"
		a.State.MainStatusColor = util.RED
		return
	}

	flagsDec, err := encoding.Decode(a.rsCodecs.RS5, flags, false)
	if err != nil {
		a.State.MainStatus = "The volume header is damaged"
		a.State.MainStatusColor = util.RED
		return
	}

	// Parse flags
	flagsStruct := header.FlagsFromBytes(flagsDec)
	if flagsStruct.UseKeyfiles {
		a.State.Keyfile = true
		a.State.KeyfileLabel = "Keyfiles required"
	} else {
		a.State.KeyfileLabel = "Not applicable"
	}
	if flagsStruct.KeyfileOrdered {
		a.State.KeyfileOrdered = true
	}

	// Check for deniability
	if volume.IsDeniable(a.State.InputFile, a.rsCodecs) {
		a.State.Deniability = true
	}
}

// handleMultipleDrop handles multiple files/folders being dropped.
// Matches original lines 1081-1131 exactly.
func (a *App) handleMultipleDrop(names []string) {
	a.State.Mode = "encrypt"
	a.State.StartLabel = "Zip and Encrypt"
	files, folders := 0, 0

	// Go through each dropped item and add to corresponding slices
	for _, name := range names {
		stat, err := os.Stat(name)
		if err != nil {
			a.State.MainStatus = "Failed to stat dropped items"
			a.State.MainStatusColor = util.RED
			fyne.Do(func() {
				a.resetUI()
				a.refreshUI()
			})
			return
		}
		if stat.IsDir() {
			folders++
			a.State.OnlyFolders = append(a.State.OnlyFolders, name)
		} else {
			files++
			a.State.OnlyFiles = append(a.State.OnlyFiles, name)
			a.State.AllFiles = append(a.State.AllFiles, name)

			a.State.CompressTotal += stat.Size()
			a.State.RequiredFreeSpace += stat.Size()
			a.State.InputLabel = fmt.Sprintf("Scanning files... (%s)", util.Sizeify(a.State.CompressTotal))
		}
	}

	// Update UI with the number of files and folders selected (matches original lines 1111-1125)
	if folders == 0 {
		a.State.InputLabel = fmt.Sprintf("%d files", files)
	} else if files == 0 {
		a.State.InputLabel = fmt.Sprintf("%d folders", folders)
	} else {
		if files == 1 && folders > 1 {
			a.State.InputLabel = fmt.Sprintf("1 file and %d folders", folders)
		} else if folders == 1 && files > 1 {
			a.State.InputLabel = fmt.Sprintf("%d files and 1 folder", files)
		} else if folders == 1 && files == 1 {
			a.State.InputLabel = "1 file and 1 folder"
		} else {
			a.State.InputLabel = fmt.Sprintf("%d files and %d folders", files, folders)
		}
	}

	// Set the input and output paths (matches original lines 1127-1129)
	a.State.InputFile = filepath.Join(filepath.Dir(names[0]), "encrypted-"+strconv.Itoa(int(time.Now().Unix()))) + ".zip"
	a.State.OutputFile = a.State.InputFile + ".pcv"
}

// handleKeyfileDrop processes dropped keyfiles when the modal is open.
func (a *App) handleKeyfileDrop(paths []string) bool {
	if !a.State.ShowKeyfile {
		return false
	}

	// Add keyfiles, checking for duplicates and access
	for _, path := range paths {
		// Check if duplicate
		duplicate := false
		for _, existing := range a.State.Keyfiles {
			if path == existing {
				duplicate = true
				break
			}
		}

		// Check if accessible and not a directory
		stat, err := os.Stat(path)
		if err != nil {
			a.State.ShowKeyfile = false
			a.State.MainStatus = "Keyfile read access denied"
			a.State.MainStatusColor = util.RED
			fyne.Do(func() {
				if a.keyfileModal != nil {
					a.keyfileModal.Hide()
				}
				a.resetUI()
				a.refreshUI()
			})
			return true
		}

		if !duplicate && !stat.IsDir() {
			a.State.Keyfiles = append(a.State.Keyfiles, path)
		}
	}

	// Update label
	switch len(a.State.Keyfiles) {
	case 0:
		if a.State.Keyfile {
			a.State.KeyfileLabel = "Keyfiles required"
		} else {
			a.State.KeyfileLabel = "None selected"
		}
	case 1:
		a.State.KeyfileLabel = "Using 1 keyfile"
	default:
		a.State.KeyfileLabel = "Using " + strconv.Itoa(len(a.State.Keyfiles)) + " keyfiles"
	}

	// Update the keyfile list in the modal and increment modalId like original
	a.State.ModalID++
	fyne.Do(func() {
		a.updateKeyfileList()
		a.refreshUI()
	})
	return true
}
