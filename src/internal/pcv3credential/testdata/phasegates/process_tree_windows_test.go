//go:build windows

package main

import (
	"errors"
	"os/exec"
	"reflect"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsProcessTreeConfiguresKillOnClose(t *testing.T) {
	api := &fakeWindowsAPI{}
	tree, err := newWindowsProcessTree(exec.Command("unused"), api)
	if err != nil {
		t.Fatalf("construct Windows process tree with fake API: %v", err)
	}
	if !api.killOnCloseConfigured ||
		windowsJobLimitFlags != windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE ||
		windowsJobLimitFlags&(windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK|
			windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0 {
		t.Fatal("Windows job is not strict kill-on-close without breakaway")
	}
	if tree.cmd.SysProcAttr == nil ||
		tree.cmd.SysProcAttr.CreationFlags != windows.CREATE_SUSPENDED {
		t.Fatal("Windows child is not created suspended before assignment")
	}
	if err := tree.Close(); err != nil {
		t.Fatalf("close fake Windows job: %v", err)
	}
	if !reflect.DeepEqual(api.calls, []string{"create-job", "kill-on-close", "close-job"}) {
		t.Fatalf("Windows job setup/cleanup order = %#v", api.calls)
	}
}

func TestWindowsProcessTreeRequiresOnePrimaryThreadAndExactResume(t *testing.T) {
	api := &fakeWindowsAPI{
		threads:         []windows.ThreadEntry32{{ThreadID: 41, OwnerProcessID: 7}},
		previousSuspend: 1,
	}
	tree := &windowsProcessTree{api: api, job: 1}
	if err := tree.resumeSolePrimaryThread(7); err != nil {
		t.Fatalf("resume exact suspended primary thread: %v", err)
	}
	want := []string{
		"snapshot", "first-thread", "next-thread", "open-thread",
		"resume-thread", "close-thread", "close-snapshot",
	}
	if !reflect.DeepEqual(api.calls, want) {
		t.Fatalf("Windows assignment/resume cleanup order = %#v; want %#v", api.calls, want)
	}

	for _, test := range []struct {
		name     string
		threads  []windows.ThreadEntry32
		previous uint32
	}{
		{name: "no primary thread"},
		{
			name: "ambiguous primary threads",
			threads: []windows.ThreadEntry32{
				{ThreadID: 1, OwnerProcessID: 7},
				{ThreadID: 2, OwnerProcessID: 7},
			},
		},
		{
			name:     "wrong suspend count",
			threads:  []windows.ThreadEntry32{{ThreadID: 1, OwnerProcessID: 7}},
			previous: 2,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &fakeWindowsAPI{
				threads:         test.threads,
				previousSuspend: test.previous,
			}
			tree := &windowsProcessTree{api: api, job: 1}
			if err := tree.resumeSolePrimaryThread(7); err == nil {
				t.Fatal("unsafe Windows thread state unexpectedly resumed")
			}
		})
	}
}

type fakeWindowsAPI struct {
	calls                 []string
	killOnCloseConfigured bool
	threads               []windows.ThreadEntry32
	threadIndex           int
	previousSuspend       uint32
}

func (api *fakeWindowsAPI) createJob() (windows.Handle, error) {
	api.calls = append(api.calls, "create-job")
	return 1, nil
}

func (api *fakeWindowsAPI) setKillOnClose(_ windows.Handle) error {
	api.calls = append(api.calls, "kill-on-close")
	api.killOnCloseConfigured = true
	return nil
}

func (api *fakeWindowsAPI) assign(_, _ windows.Handle) error {
	api.calls = append(api.calls, "assign")
	return nil
}

func (api *fakeWindowsAPI) threadSnapshot() (windows.Handle, error) {
	api.calls = append(api.calls, "snapshot")
	return 2, nil
}

func (api *fakeWindowsAPI) firstThread(
	_ windows.Handle,
	entry *windows.ThreadEntry32,
) error {
	api.calls = append(api.calls, "first-thread")
	api.threadIndex = 0
	if len(api.threads) == 0 {
		return windows.ERROR_NO_MORE_FILES
	}
	*entry = api.threads[0]
	return nil
}

func (api *fakeWindowsAPI) nextThread(
	_ windows.Handle,
	entry *windows.ThreadEntry32,
) error {
	api.calls = append(api.calls, "next-thread")
	api.threadIndex++
	if api.threadIndex >= len(api.threads) {
		return windows.ERROR_NO_MORE_FILES
	}
	*entry = api.threads[api.threadIndex]
	return nil
}

func (api *fakeWindowsAPI) openThread(_ uint32) (windows.Handle, error) {
	api.calls = append(api.calls, "open-thread")
	return 3, nil
}

func (api *fakeWindowsAPI) resumeThread(_ windows.Handle) (uint32, error) {
	api.calls = append(api.calls, "resume-thread")
	return api.previousSuspend, nil
}

func (api *fakeWindowsAPI) terminateJob(_ windows.Handle) error {
	api.calls = append(api.calls, "terminate-job")
	return nil
}

func (api *fakeWindowsAPI) activeProcesses(_ windows.Handle) (uint32, error) {
	api.calls = append(api.calls, "active-processes")
	return 0, nil
}

func (api *fakeWindowsAPI) closeHandle(handle windows.Handle) error {
	switch handle {
	case 1:
		api.calls = append(api.calls, "close-job")
	case 2:
		api.calls = append(api.calls, "close-snapshot")
	case 3:
		api.calls = append(api.calls, "close-thread")
	default:
		return errors.New("unexpected fake Windows handle")
	}
	return nil
}
