package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

// normalRSBodyWriter copies every accepted byte. Borrowed write slices are
// retained only as test cleanup observers; they are never read as output.
type normalRSBodyWriter struct {
	written            bytes.Buffer
	bodyStart          int
	faultAfter         int
	fault              string
	cause              error
	cancel             context.CancelFunc
	checkpointContext  *recordRSCancelContext
	armed              bool
	failed             bool
	writesAfterFailure int
	bodyWrites         []int
	borrowed           [][]byte
}

func (writer *normalRSBodyWriter) Write(data []byte) (int, error) {
	if writer.failed {
		writer.writesAfterFailure++
		return 0, writer.cause
	}
	start := writer.written.Len()
	if start >= writer.bodyStart && start < writer.bodyStart+1_114_248 {
		writer.bodyWrites = append(writer.bodyWrites, len(data))
	}
	writer.borrowed = append(writer.borrowed, data)
	if start >= writer.faultAfter && writer.faultAfter != 0 {
		switch writer.fault {
		case "short":
			writer.failed = true
			return writer.written.Write(data[:len(data)-1])
		case "error":
			writer.failed = true
			count, _ := writer.written.Write(data[:len(data)/2])
			return count, writer.cause
		}
	}
	count, err := writer.written.Write(data)
	if !writer.armed && writer.faultAfter != 0 && writer.written.Len() >= writer.faultAfter {
		writer.armed = true
		switch writer.fault {
		case "cancel":
			writer.cancel()
		case "cancel-during-next-batch":
			// Let normalExactWriter's post-write check and the first next-word check
			// complete, then cancel through the real Context during pending encoding.
			writer.checkpointContext.active = true
			writer.checkpointContext.remaining = 2
		}
	}
	return count, err
}

func TestWriteNormalRecordsRSFullRecordFrozenBytesAndBodyFailures(t *testing.T) {
	fixture := recordFixtureByName(t, loadRecordFixtureManifest(t), "exact_one_paranoid_rs")
	core := loadRecordFixtureCore(t, fixture)
	geometry := recordFixtureGeometry(t, fixture, core)
	plaintext := recordFixturePlaintext(t, fixture)
	frozen := assembleRecordFixturePayload(t, fixture)
	literalKeys := recordFixtureFile(t, fixture.KeysFile)
	defer pcv3crypto.SecureZero(literalKeys)
	if len(literalKeys) != 96 {
		t.Fatal("frozen record fixture must contain three 32-byte payload keys")
	}
	codecs := recordTestCodecs(t)
	const firstBatchEnd = 48 + 256*136
	for _, mode := range []string{"success", "short", "error", "cancel", "cancel-during-next-batch"} {
		t.Run(mode, func(t *testing.T) {
			var keys normalWriteKeys
			copy(keys.payloadXChaCha20[:], literalKeys[:32])
			copy(keys.payloadSerpent[:], literalKeys[32:64])
			copy(keys.payloadMAC[:], literalKeys[64:])
			defer keys.close()
			realContext, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &recordRSCancelContext{Context: realContext, cancel: cancel}
			cause := errors.New("TEST ONLY RS body sink failure")
			destination := &normalRSBodyWriter{bodyStart: 48, fault: mode, cause: cause, cancel: cancel, checkpointContext: ctx}
			if mode != "success" {
				destination.faultAfter = firstBatchEnd
			}
			writer := &normalExactWriter{ctx: ctx, destination: destination, offset: fixture.FrontHeaderLength}
			err := writeNormalRecords(ctx, bytes.NewReader(plaintext), writer, core, geometry, &keys, codecs)
			if mode == "success" {
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(destination.written.Bytes(), frozen) {
					t.Fatal("1 MiB RS writer differs from independent frozen data+tag+padding+final payload")
				}
				// Explicit performance/I/O policy: batches are bounded to 256 codewords.
				// Exact stream bytes above are the product oracle, independent of writes.
				for _, size := range destination.bodyWrites {
					if size > 256*136 {
						t.Fatalf("RS body write %d exceeds 256-word bounded I/O policy", size)
					}
				}
				if len(destination.bodyWrites) < 2 || destination.bodyWrites[len(destination.bodyWrites)-1] != 136 {
					t.Fatal("full record did not reach the final one-word partial body batch")
				}
			} else {
				var failure *normalWriteFailure
				if !errors.As(err, &failure) {
					t.Fatalf("failed RS body returned success or unclassified error: %v", err)
				}
				switch mode {
				case "short":
					if failure.Stage() != StageOutputWrite || !errors.Is(err, io.ErrShortWrite) {
						t.Fatalf("short body write = %v/%v", failure.Stage(), err)
					}
				case "error":
					if failure.Stage() != StageOutputWrite || !errors.Is(err, cause) {
						t.Fatalf("partial body error = %v/%v", failure.Stage(), err)
					}
				default:
					if failure.Stage() != StageCancellation || !errors.Is(err, context.Canceled) {
						t.Fatalf("body cancellation = %v/%v", failure.Stage(), err)
					}
					select {
					case <-ctx.Done():
					default:
						t.Fatal("cancellation did not close real Context.Done")
					}
					if destination.written.Len() != firstBatchEnd {
						t.Fatalf("canceled pending RS batch emitted extra bytes: got %d, want frozen prefix %d", destination.written.Len(), firstBatchEnd)
					}
				}
				if destination.written.Len() >= int(fixture.Records[1].DescriptorOffset) || destination.writesAfterFailure != 0 {
					t.Fatal("body failure wrote final record or retried output")
				}
				if !bytes.Equal(destination.written.Bytes(), frozen[:destination.written.Len()]) {
					t.Fatal("successful/partial body writes differ from frozen encoded prefix")
				}
				if writer.offset != fixture.FrontHeaderLength+uint64(destination.written.Len()) {
					t.Fatal("body failure lost exact accepted-byte offset")
				}
			}
			for _, borrowed := range destination.borrowed {
				if !recordPaddingIsZero(borrowed) {
					t.Fatal("RS body exit retained writer-owned encoded batch or descriptor bytes")
				}
			}
		})
	}
}
