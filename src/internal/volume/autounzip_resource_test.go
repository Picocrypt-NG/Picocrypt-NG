package volume

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func legacyResourceArchive(t *testing.T) []byte {
	t.Helper()
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	if _, err := writer.Create("payload.txt"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return legacyResourceZIP64(t, data.Bytes(), math.MaxUint64)
}

func TestLegacyAutoUnzipResourceRefusalNeverPublishesArchive(t *testing.T) {
	var nested bytes.Buffer
	writer := zip.NewWriter(&nested)
	if _, err := writer.Create(strings.Repeat("a/", 12000) + "leaf"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"metadata": legacyResourceArchive(t), "workspace": nested.Bytes()} {
		t.Run(name, func(t *testing.T) {
			for _, sameLevel := range []bool{false, true} {
				for _, suffix := range []string{"", ".zip"} {
					t.Run(fmt.Sprintf("same_level=%t%s", sameLevel, suffix), func(t *testing.T) {
						dir := t.TempDir()
						source := filepath.Join(dir, "encrypted.pcv")
						if err := os.WriteFile(source, []byte("preserve encrypted input"), 0o600); err != nil {
							t.Fatal(err)
						}
						sourceInfo, err := os.Stat(source)
						if err != nil {
							t.Fatal(err)
						}
						output := filepath.Join(dir, "output"+suffix)
						ctx := legacyResourceFinalizeContext(t, output, data)
						ctx.protectedInputInfos = []os.FileInfo{sourceInfo}
						err = decryptFinalize(ctx, &DecryptRequest{InputFile: source, OutputFile: output, AutoUnzip: true, SameLevel: sameLevel})
						if !errors.Is(err, fileops.ErrZIPMetadataLimit) {
							t.Fatalf("want resource refusal, got %v", err)
						}
						if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
							t.Errorf("resource refusal published plaintext archive: %v", err)
						}
						if err := ctx.Close(); err != nil {
							t.Fatal(err)
						}
						assertNoPicocryptStages(t, dir)
						after, err := os.Stat(source)
						if err != nil || !os.SameFile(sourceInfo, after) {
							t.Fatalf("source identity changed: %v", err)
						}
						assertFileBytes(t, source, []byte("preserve encrypted input"))
						entries, err := os.ReadDir(dir)
						if err != nil || len(entries) != 1 {
							t.Fatalf("resource refusal left output: %v %v", entries, err)
						}
					})
				}
			}
		})
	}
}

func legacyResourceFinalizeContext(t *testing.T, output string, data []byte) *OperationContext {
	t.Helper()
	mac := sha256.New()
	suite, err := crypto.NewCipherSuite(make([]byte, 32), make([]byte, 24), nil, nil, mac, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &OperationContext{Ctx: context.Background(), OutputFile: output, CipherSuite: suite, Header: &header.VolumeHeader{AuthTag: mac.Sum(nil)}}
	if err := ctx.beginStagedOutput(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ctx.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := ctx.stagedOutput.File().Write(data); err != nil {
		t.Fatal(err)
	}
	return ctx
}

func legacyResourceZIP64(t *testing.T, archive []byte, count uint64) []byte {
	t.Helper()
	end := len(archive) - 22
	footer := append([]byte(nil), archive[end:]...)
	var extension [76]byte
	binary.LittleEndian.PutUint32(extension[:], 0x06064b50)
	binary.LittleEndian.PutUint64(extension[4:], 44)
	binary.LittleEndian.PutUint16(extension[12:], 45)
	binary.LittleEndian.PutUint16(extension[14:], 45)
	binary.LittleEndian.PutUint64(extension[24:], count)
	binary.LittleEndian.PutUint64(extension[32:], count)
	binary.LittleEndian.PutUint64(extension[40:], uint64(binary.LittleEndian.Uint32(footer[12:])))
	binary.LittleEndian.PutUint64(extension[48:], uint64(binary.LittleEndian.Uint32(footer[16:])))
	binary.LittleEndian.PutUint32(extension[56:], 0x07064b50)
	binary.LittleEndian.PutUint64(extension[64:], uint64(end))
	binary.LittleEndian.PutUint32(extension[72:], 1)
	binary.LittleEndian.PutUint16(footer[8:], 0xffff)
	binary.LittleEndian.PutUint16(footer[10:], 0xffff)
	binary.LittleEndian.PutUint32(footer[12:], 0xffffffff)
	binary.LittleEndian.PutUint32(footer[16:], 0xffffffff)
	result := append([]byte(nil), archive[:end]...)
	result = append(result, extension[:]...)
	return append(result, footer...)
}
