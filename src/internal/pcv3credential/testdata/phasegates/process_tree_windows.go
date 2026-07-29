//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsJobLimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

type windowsBasicAccounting struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

type windowsAPI interface {
	createJob() (windows.Handle, error)
	setKillOnClose(windows.Handle) error
	assign(windows.Handle, windows.Handle) error
	threadSnapshot() (windows.Handle, error)
	firstThread(windows.Handle, *windows.ThreadEntry32) error
	nextThread(windows.Handle, *windows.ThreadEntry32) error
	openThread(uint32) (windows.Handle, error)
	resumeThread(windows.Handle) (uint32, error)
	terminateJob(windows.Handle) error
	activeProcesses(windows.Handle) (uint32, error)
	closeHandle(windows.Handle) error
}

type realWindowsAPI struct{}

func (realWindowsAPI) createJob() (windows.Handle, error) {
	return windows.CreateJobObject(nil, nil)
}

func (realWindowsAPI) setKillOnClose(job windows.Handle) error {
	information := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	information.BasicLimitInformation.LimitFlags = windowsJobLimitFlags
	_, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&information)),
		uint32(unsafe.Sizeof(information)),
	)
	return err
}

func (realWindowsAPI) assign(job, process windows.Handle) error {
	return windows.AssignProcessToJobObject(job, process)
}

func (realWindowsAPI) threadSnapshot() (windows.Handle, error) {
	return windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
}

func (realWindowsAPI) firstThread(
	snapshot windows.Handle,
	entry *windows.ThreadEntry32,
) error {
	return windows.Thread32First(snapshot, entry)
}

func (realWindowsAPI) nextThread(
	snapshot windows.Handle,
	entry *windows.ThreadEntry32,
) error {
	return windows.Thread32Next(snapshot, entry)
}

func (realWindowsAPI) openThread(threadID uint32) (windows.Handle, error) {
	return windows.OpenThread(
		windows.THREAD_SUSPEND_RESUME,
		false,
		threadID,
	)
}

func (realWindowsAPI) resumeThread(thread windows.Handle) (uint32, error) {
	return windows.ResumeThread(thread)
}

func (realWindowsAPI) terminateJob(job windows.Handle) error {
	return windows.TerminateJobObject(job, 1)
}

func (realWindowsAPI) activeProcesses(job windows.Handle) (uint32, error) {
	information := windowsBasicAccounting{}
	err := windows.QueryInformationJobObject(
		job,
		windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&information)),
		uint32(unsafe.Sizeof(information)),
		nil,
	)
	return information.ActiveProcesses, err
}

func (realWindowsAPI) closeHandle(handle windows.Handle) error {
	return windows.CloseHandle(handle)
}

type windowsProcessTree struct {
	cmd      *exec.Cmd
	api      windowsAPI
	mu       sync.Mutex
	job      windows.Handle
	started  bool
	assigned bool
	waited   bool
	closed   bool
}

func processTreeSupported() error {
	return errors.New("stage execution is runtime-verified only on Linux")
}

func fileLinkCount(os.FileInfo) (uint64, bool) {
	return 0, false
}

func openEvidenceRootHandle(string) (*os.File, error) {
	return nil, errors.New("stage execution is runtime-verified only on Linux")
}

func createEvidenceFileAt(*os.File, string) (*os.File, error) {
	return nil, errors.New("stage execution is runtime-verified only on Linux")
}

func openReadFileAt(*os.File, string) (*os.File, error) {
	return nil, errors.New("stage execution is runtime-verified only on Linux")
}

func makeDirectoryAt(*os.File, string, uint32) error {
	return errors.New("stage execution is runtime-verified only on Linux")
}

func removeDirectoryAt(*os.File, string) error {
	return errors.New("stage execution is runtime-verified only on Linux")
}

func linkPublicationProofAt(*os.File, string, string) error {
	return errors.New("stage execution is runtime-verified only on Linux")
}

func newProcessTree(cmd *exec.Cmd) (processTree, error) {
	return newWindowsProcessTree(cmd, realWindowsAPI{})
}

func newWindowsProcessTree(
	cmd *exec.Cmd,
	api windowsAPI,
) (*windowsProcessTree, error) {
	if cmd == nil || api == nil {
		return nil, errors.New("nil Windows process-tree dependency")
	}
	job, err := api.createJob()
	if err != nil {
		return nil, fmt.Errorf("create Windows job: %w", err)
	}
	if err := api.setKillOnClose(job); err != nil {
		return nil, errors.Join(
			fmt.Errorf("set Windows job kill-on-close: %w", err),
			api.closeHandle(job),
		)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_SUSPENDED,
	}
	return &windowsProcessTree{cmd: cmd, api: api, job: job}, nil
}

func (tree *windowsProcessTree) Start() error {
	tree.mu.Lock()
	defer tree.mu.Unlock()
	if tree.started {
		return errors.New("process tree already started")
	}
	if err := tree.cmd.Start(); err != nil {
		return errors.Join(err, tree.closeLocked())
	}
	tree.started = true

	var assignErr error
	withHandleErr := tree.cmd.Process.WithHandle(func(handle uintptr) {
		assignErr = tree.api.assign(tree.job, windows.Handle(handle))
	})
	if withHandleErr != nil || assignErr != nil {
		return tree.failStartedBeforeAssignmentLocked(errors.Join(withHandleErr, assignErr))
	}
	tree.assigned = true
	if err := tree.resumeSolePrimaryThread(uint32(tree.cmd.Process.Pid)); err != nil {
		return tree.failStartedAfterAssignmentLocked(err)
	}
	return nil
}

func (tree *windowsProcessTree) resumeSolePrimaryThread(pid uint32) error {
	snapshot, err := tree.api.threadSnapshot()
	if err != nil {
		return fmt.Errorf("snapshot suspended process threads: %w", err)
	}
	defer func() {
		_ = tree.api.closeHandle(snapshot)
	}()
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	var threadIDs []uint32
	if err := tree.api.firstThread(snapshot, &entry); err != nil {
		return fmt.Errorf("enumerate suspended process threads: %w", err)
	}
	for {
		if entry.OwnerProcessID == pid {
			threadIDs = append(threadIDs, entry.ThreadID)
		}
		entry.Size = uint32(unsafe.Sizeof(windows.ThreadEntry32{}))
		err = tree.api.nextThread(snapshot, &entry)
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			break
		}
		if err != nil {
			return fmt.Errorf("enumerate suspended process threads: %w", err)
		}
	}
	if len(threadIDs) != 1 {
		return fmt.Errorf(
			"suspended process thread count = %d; want exactly 1",
			len(threadIDs),
		)
	}
	thread, err := tree.api.openThread(threadIDs[0])
	if err != nil {
		return fmt.Errorf("open suspended primary thread: %w", err)
	}
	defer func() {
		_ = tree.api.closeHandle(thread)
	}()
	previous, err := tree.api.resumeThread(thread)
	if err != nil {
		return fmt.Errorf("resume suspended primary thread: %w", err)
	}
	if previous != 1 {
		return fmt.Errorf(
			"primary thread previous suspend count = %d; want exactly 1",
			previous,
		)
	}
	return nil
}

func (tree *windowsProcessTree) failStartedBeforeAssignmentLocked(cause error) error {
	killErr := tree.cmd.Process.Kill()
	waitErr := tree.waitAfterFailedStartLocked()
	closeErr := tree.closeLocked()
	return errors.Join(cause, killErr, waitErr, closeErr)
}

func (tree *windowsProcessTree) failStartedAfterAssignmentLocked(cause error) error {
	terminateErr := tree.terminateLocked()
	waitErr := tree.waitAfterFailedStartLocked()
	closeErr := tree.closeLocked()
	return errors.Join(cause, terminateErr, waitErr, closeErr)
}

func (tree *windowsProcessTree) Terminate() error {
	tree.mu.Lock()
	defer tree.mu.Unlock()
	return tree.terminateLocked()
}

func (tree *windowsProcessTree) terminateLocked() error {
	if !tree.started {
		return nil
	}
	if !tree.assigned {
		return tree.cmd.Process.Kill()
	}
	return tree.api.terminateJob(tree.job)
}

func (tree *windowsProcessTree) Wait() error {
	tree.mu.Lock()
	if !tree.started {
		tree.mu.Unlock()
		return errors.New("cannot wait before process start")
	}
	if tree.waited {
		tree.mu.Unlock()
		return errors.New("process wait called more than once")
	}
	tree.waited = true
	tree.mu.Unlock()
	return tree.cmd.Wait()
}

func (tree *windowsProcessTree) waitAfterFailedStartLocked() error {
	if tree.waited {
		return errors.New("process wait called more than once")
	}
	tree.waited = true
	tree.mu.Unlock()
	err := tree.cmd.Wait()
	tree.mu.Lock()
	return err
}

func (tree *windowsProcessTree) Active() (bool, error) {
	tree.mu.Lock()
	defer tree.mu.Unlock()
	if !tree.started || !tree.assigned {
		return false, nil
	}
	active, err := tree.api.activeProcesses(tree.job)
	return active != 0, err
}

func (tree *windowsProcessTree) Close() error {
	tree.mu.Lock()
	defer tree.mu.Unlock()
	return tree.closeLocked()
}

func (tree *windowsProcessTree) closeLocked() error {
	if tree.closed || tree.job == 0 {
		return nil
	}
	tree.closed = true
	return tree.api.closeHandle(tree.job)
}
