//go:build linux || darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

type unixProcessTree struct {
	cmd     *exec.Cmd
	mu      sync.Mutex
	pid     int
	started bool
	waited  bool
}

func processTreeSupported() error {
	if runtime.GOOS != "linux" {
		return errors.New("stage execution is runtime-verified only on Linux")
	}
	return nil
}

func fileLinkCount(info os.FileInfo) (uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(stat.Nlink), true //nolint:unconvert // Darwin's Stat_t.Nlink is narrower.
}

func openEvidenceRootHandle(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func createEvidenceFileAt(root *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(
		int(root.Fd()),
		name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func openReadFileAt(root *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(
		int(root.Fd()),
		name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func makeDirectoryAt(root *os.File, name string, mode uint32) error {
	return unix.Mkdirat(int(root.Fd()), name, mode)
}

func removeDirectoryAt(root *os.File, name string) error {
	return unix.Unlinkat(int(root.Fd()), name, unix.AT_REMOVEDIR)
}

func linkPublicationProofAt(root *os.File, pendingName, finalName string) error {
	return linkPublicationProofAtWithUnlink(
		root,
		pendingName,
		finalName,
		unix.Unlinkat,
	)
}

func linkPublicationProofAtWithUnlink(
	root *os.File,
	pendingName string,
	finalName string,
	unlinkAt func(int, string, int) error,
) error {
	if err := unix.Linkat(
		int(root.Fd()),
		pendingName,
		int(root.Fd()),
		finalName,
		0,
	); err != nil {
		return err
	}
	return unlinkAt(int(root.Fd()), pendingName, 0)
}

func newProcessTree(cmd *exec.Cmd) (processTree, error) {
	if cmd == nil {
		return nil, errors.New("nil process command")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return &unixProcessTree{cmd: cmd}, nil
}

func (tree *unixProcessTree) Start() error {
	tree.mu.Lock()
	defer tree.mu.Unlock()
	if tree.started {
		return errors.New("process tree already started")
	}
	if err := tree.cmd.Start(); err != nil {
		return err
	}
	tree.started = true
	tree.pid = tree.cmd.Process.Pid
	return nil
}

func (tree *unixProcessTree) Terminate() error {
	tree.mu.Lock()
	defer tree.mu.Unlock()
	if !tree.started || tree.pid <= 0 {
		return nil
	}
	err := unix.Kill(-tree.pid, unix.SIGKILL)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func (tree *unixProcessTree) Wait() error {
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

func (tree *unixProcessTree) Active() (bool, error) {
	tree.mu.Lock()
	defer tree.mu.Unlock()
	if !tree.started || tree.pid <= 0 {
		return false, nil
	}
	if runtime.GOOS == "linux" {
		return linuxProcessGroupActive(tree.pid)
	}
	err := unix.Kill(-tree.pid, 0)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.ESRCH):
		return false, nil
	case errors.Is(err, unix.EPERM):
		return true, nil
	default:
		return false, err
	}
}

func (tree *unixProcessTree) Close() error {
	return nil
}

func linuxProcessGroupActive(processGroupID int) (bool, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, fmt.Errorf("read Linux process table: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("read Linux process state: %w", err)
		}
		closingParen := strings.LastIndexByte(string(data), ')')
		if closingParen < 0 {
			return false, errors.New("malformed Linux process state")
		}
		fields := strings.Fields(string(data[closingParen+1:]))
		if len(fields) < 3 {
			return false, errors.New("incomplete Linux process state")
		}
		groupID, err := strconv.Atoi(fields[2])
		if err != nil {
			return false, errors.New("invalid Linux process group")
		}
		if groupID == processGroupID && fields[0] != "Z" {
			return true, nil
		}
	}
	return false, nil
}
