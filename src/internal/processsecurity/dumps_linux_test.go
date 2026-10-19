//go:build linux && !android

package processsecurity

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDisableDumpsRequiresSuccessfulSetAndZeroReadback(t *testing.T) {
	denied := errors.New("denied")
	for _, tc := range []struct {
		name     string
		setErr   error
		getErr   error
		readback int
		wantErr  bool
	}{
		{name: "set denied", setErr: denied, wantErr: true},
		{name: "readback denied", getErr: denied, wantErr: true},
		{name: "still owner dumpable", readback: 1, wantErr: true},
		{name: "still privileged dumpable", readback: 2, wantErr: true},
		{name: "disabled", readback: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setDone := false
			err := disableDumps(func() error { setDone = true; return tc.setErr }, func() (int, error) {
				if !setDone || tc.setErr != nil {
					t.Fatal("readback before successful SET")
				}
				return tc.readback, tc.getErr
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("disableDumps() = %v; want error %v", err, tc.wantErr)
			}
			if tc.setErr != nil && !errors.Is(err, tc.setErr) {
				t.Fatalf("SET cause lost: %v", err)
			}
			if tc.getErr != nil && !errors.Is(err, tc.getErr) {
				t.Fatalf("GET cause lost: %v", err)
			}
		})
	}
}

func TestSnapExemptionRequiresThePackagedExecutable(t *testing.T) {
	for _, tc := range []struct {
		root, executable string
		want             bool
	}{
		{"/snap/picocrypt-ng/12", "/snap/picocrypt-ng/12/bin/Picocrypt-NG", true},
		{"/var/lib/snapd/snap/picocrypt-ng/12", "/var/lib/snapd/snap/picocrypt-ng/12/bin/Picocrypt-NG", true},
		{"/snap/picocrypt-ng_work/x1", "/snap/picocrypt-ng_work/x1/bin/Picocrypt-NG", true},
		{"/snap/picocrypt-ng/12", "/home/test/Picocrypt-NG", false},
		{"/tmp/picocrypt-ng/12", "/tmp/picocrypt-ng/12/bin/Picocrypt-NG", false},
		{"/snap/another-app/12", "/snap/another-app/12/bin/Picocrypt-NG", false},
		{"/snap/picocrypt-ng/12", "/snap/picocrypt-ng/12/bin/unrelated", false},
		{"/snap/picocrypt-ng/12/extra", "/snap/picocrypt-ng/12/extra/bin/Picocrypt-NG", false},
		{"/snap/picocrypt-ng_/12", "/snap/picocrypt-ng_/12/bin/Picocrypt-NG", false},
	} {
		t.Run(tc.root+":"+tc.executable, func(t *testing.T) {
			if got := isSnapExecutable(tc.root, tc.executable); got != tc.want {
				t.Fatalf("isSnapExecutable() = %v; want %v", got, tc.want)
			}
		})
	}
}

// One SET must affect existing Go workers sharing the address space. A child
// changes only its own policy; the parent test process must remain untouched.
func TestRestrictDumpsAffectsAllWorkersWithoutChangingParent(t *testing.T) {
	if info, err := os.Stat("/.flatpak-info"); err == nil && info.Mode().IsRegular() {
		t.Skip("Flatpak packages intentionally retain their existing dump policy")
	}
	if os.Getenv("PICOCRYPT_DUMP_WORKERS_CHILD") == "1" {
		const workers = 6
		ready := make(chan struct{}, workers)
		read := make(chan struct{})
		states := make(chan int, workers)
		var wg sync.WaitGroup
		for range workers {
			wg.Go(func() {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				ready <- struct{}{}
				<-read
				state, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
				if err != nil {
					state = -1
				}
				states <- state
			})
		}
		for range workers {
			<-ready
		}
		if err := RestrictDumps(); err != nil {
			t.Fatal(err)
		}
		close(read)
		wg.Wait()
		for range workers {
			if got := <-states; got != 0 {
				t.Errorf("worker dumpable = %d; want 0", got)
			}
		}
		return
	}
	before, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRestrictDumpsAffectsAllWorkersWithoutChangingParent$")
	cmd.Env = append(os.Environ(), "PICOCRYPT_DUMP_WORKERS_CHILD=1", "FLATPAK_ID=io.github.picocrypt_ng.Picocrypt-NG", "SNAP=/tmp/picocrypt-ng/12")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	after, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil || after != before {
		t.Fatalf("parent dumpability changed: before=%d after=%d error=%v", before, after, err)
	}
}
