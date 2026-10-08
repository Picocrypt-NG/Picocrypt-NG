//go:build windows

package pcv3resource

import (
	"context"
	"io"
	"os"
	"os/exec"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Exercise the real observer on the execution host. The same product process
// must expose headroom outside jobs and refuse it when an unknown ancestor job
// can constrain commit. The logged facts distinguish these CI environments.
func TestWindowsNativeResourceSnapshotMatchesObservedJobBoundary(t *testing.T) {
	status, statusOK := readWindowsMemoryStatus()
	privateCommit, privateOK := readWindowsPrivateCommit()
	outsideJob := windowsProcessOutsideJob()
	snapshot := newPlatformSnapshotProvider().Snapshot(context.Background())
	t.Logf("native Windows memory: statusOK=%t privateOK=%t outsideJob=%t physical=%d commit=%d virtual=%d private=%d snapshotState=%d headroom=%d reserve=%d",
		statusOK, privateOK, outsideJob, status.availablePhysical, status.availableCommit,
		status.availableVirtual, privateCommit, snapshot.state, snapshot.effectiveAvailable, snapshot.codeOwnedReserve)
	if snapshot.source != snapshotSourceWindows || snapshot.platformThreshold != 0 ||
		snapshot.sequence == 0 || snapshot.observedAt.IsZero() {
		t.Fatalf("native snapshot has invalid source or observation metadata: %+v", snapshot)
	}
	if outsideJob && statusOK && privateOK && privateCommit <= status.totalCommit {
		if snapshot.state != snapshotStateReady || snapshot.effectiveAvailable == 0 || snapshot.codeOwnedReserve == 0 {
			t.Fatalf("valid native facts outside jobs must supply genuine admission headroom: %+v", snapshot)
		}
		return
	}
	if snapshot.state != snapshotStateUnknown || snapshot.effectiveAvailable != 0 || snapshot.codeOwnedReserve != 0 {
		t.Fatalf("uncertain native facts must not supply admission headroom: %+v", snapshot)
	}
}

// A child with a roomy immediate job still has an ancestor whose constraints
// cannot be established by QueryInformationJobObject(NULL). Exercise actual
// job membership and the production snapshot, without allocating a KDF.
func TestWindowsNestedJobAdmissionFailsClosed(t *testing.T) {
	const childFlag = "PICOCRYPT_TEST_NESTED_JOB_CHILD"
	if os.Getenv(childFlag) == "1" {
		var signal [1]byte
		if _, err := io.ReadFull(os.Stdin, signal[:]); err != nil {
			t.Fatal(err)
		}
		if windowsProcessOutsideJob() {
			t.Fatal("child is not observed inside its assigned jobs")
		}
		snapshot := (windowsSnapshotProvider{}).Snapshot(context.Background())
		if snapshot.state != snapshotStateUnknown || snapshot.effectiveAvailable != 0 {
			t.Fatalf("nested job snapshot = %+v; want unknown without admission headroom", snapshot)
		}
		return
	}

	parentJob, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(parentJob)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_JOB_MEMORY
	limits.JobMemoryLimit = 512 << 20
	if _, err := windows.SetInformationJobObject(parentJob, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		t.Fatalf("set ancestor commit limit: %v", err)
	}
	childJob, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(childJob)
	command := exec.Command(os.Args[0], "-test.run=^TestWindowsNestedJobAdmissionFailsClosed$", "-test.timeout=30s")
	command.Env = append(os.Environ(), childFlag+"=1")
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}()
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(command.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(process)
	if err := windows.AssignProcessToJobObject(parentJob, process); err != nil {
		t.Fatalf("assign ancestor job: %v", err)
	}
	if err := windows.AssignProcessToJobObject(childJob, process); err != nil {
		t.Fatalf("assign immediate nested job: %v", err)
	}
	if _, err := input.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
}
