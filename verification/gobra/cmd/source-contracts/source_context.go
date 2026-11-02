package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const sourceContextScope = "all regular non-test .go and go.mod/go.sum files recursively under src, including required src/go.mod and src/go.sum; inventory and streamed SHA256 only"

type sourceContext struct {
	Scope  string            `json:"scope"`
	Files  map[string]string `json:"file_sha256"`
	SHA256 string            `json:"inventory_sha256"`
}

func sourceContextFile(path string) (value string, err error) {
	entry, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !entry.Mode().IsRegular() {
		return "", fmt.Errorf("source context input is not a regular file: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("source context input is not a regular file: %s", path)
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func captureSourceContext(repo string) (sourceContext, error) {
	result := sourceContext{Scope: sourceContextScope, Files: map[string]string{}}
	add := func(path string) error {
		relative, err := filepath.Rel(repo, path)
		if err != nil {
			return err
		}
		value, err := sourceContextFile(path)
		if err != nil {
			return err
		}
		result.Files[filepath.ToSlash(relative)] = value
		return nil
	}
	err := filepath.WalkDir(filepath.Join(repo, "src"), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		goInput := strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go")
		moduleInput := entry.Name() == "go.mod" || entry.Name() == "go.sum"
		if entry.Type()&os.ModeSymlink != 0 {
			followed, err := os.Stat(path)
			if goInput || moduleInput || err == nil && followed.IsDir() {
				return fmt.Errorf("source context requires review of symlink: %s", path)
			}
			return nil
		}
		if entry.IsDir() && moduleInput {
			return fmt.Errorf("source module input is not a regular file: %s", path)
		}
		if entry.IsDir() || !goInput && !moduleInput {
			return nil
		}
		return add(path)
	})
	if err != nil {
		return result, err
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		path := filepath.Join(repo, "src", name)
		info, err := os.Lstat(path)
		if err != nil {
			return result, err
		}
		if !info.Mode().IsRegular() {
			return result, fmt.Errorf("source module input is not a regular file: %s", path)
		}
		if err = add(path); err != nil {
			return result, err
		}
	}
	paths := make([]string, 0, len(result.Files))
	for path := range result.Files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	hash := sha256.New()
	for _, path := range paths {
		if _, err = io.WriteString(hash, path+"\x00"+result.Files[path]+"\x00"); err != nil {
			return result, err
		}
	}
	result.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return result, nil
}

func checkSourceContext(repo string, before sourceContext) (sourceContext, error) {
	current, err := captureSourceContext(repo)
	if err != nil {
		return current, err
	}
	if before.Scope != sourceContextScope {
		return current, errors.New("source context baseline has an unreviewed scope")
	}
	paths := make([]string, 0, len(before.Files)+len(current.Files))
	for path := range before.Files {
		paths = append(paths, path)
	}
	for path := range current.Files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range slices.Compact(paths) {
		previous, existed := before.Files[path]
		value, exists := current.Files[path]
		switch {
		case !existed:
			return current, fmt.Errorf("source context added input: %s", path)
		case !exists:
			return current, fmt.Errorf("source context deleted input: %s", path)
		case previous != value:
			return current, fmt.Errorf("source context changed input: %s", path)
		}
	}
	if before.SHA256 != current.SHA256 {
		return current, errors.New("source context inventory fingerprint changed")
	}
	return current, nil
}
