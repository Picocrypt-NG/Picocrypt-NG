//go:build windows

package pcv3publication

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This is additional restricted-token DACL evidence, not a different-account
// test: the effective token retains the parent's user SID. The restricting SID
// adds a second access check which an owner-only DACL must refuse.
func TestWindowsPrivateStageRejectsRestrictedTokenContext(t *testing.T) {
	if os.Getenv("PICOCRYPT_CUSTODY_RESTRICTED_CHILD") == "1" {
		checkRestrictedStageAccess(t)
		return
	}
	directory := t.TempDir()
	stage, err := Create(filepath.Join(directory, "output"), nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	payload := []byte("private bytes remain unchanged after restricted access")
	if _, err := stage.File().Write(payload); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(directory, "allowed-control")
	if err := os.WriteFile(control, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(control, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestWindowsPrivateStageRejectsRestrictedTokenContext$", "-test.v")
	command.Env = append(os.Environ(), "PICOCRYPT_CUSTODY_RESTRICTED_CHILD=1", "PICOCRYPT_CUSTODY_STAGE="+stage.stagePath, "PICOCRYPT_CUSTODY_CONTROL="+control)
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("restricted context control and denial verified")) {
		t.Fatalf("restricted context child did not prove both access checks: %v\n%s", err, output)
	}
	requireFileBytes(t, stage.stagePath, payload)
	requireFileBytes(t, control, payload)
	if !stage.stageIdentityCurrent() {
		t.Fatal("restricted access changed the original stage identity")
	}
	stagePath := stage.stagePath
	if err := stage.Cleanup(); err != nil && (!errors.Is(err, ErrCleanupDurabilityUncertain) || errors.Is(err, ErrCleanupIncomplete)) {
		t.Fatalf("native Windows exact cleanup failed: %v", err)
	}
	if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original stage remains after handle cleanup: %v", err)
	}
	requireFileBytes(t, control, payload)
}

func checkRestrictedStageAccess(t *testing.T) {
	t.Helper()
	var original windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &original); err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	user, err := original.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	restrictingSID, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	restriction := windows.SIDAndAttributes{Sid: restrictingSID}
	var restricted windows.Token
	// CreateRestrictedToken is documented since XP; DISABLE_MAX_PRIVILEGE
	// removes privileges except traversal. No sandbox-inert flag is used.
	createRestrictedToken := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	ok, _, callErr := createRestrictedToken.Call(uintptr(original), 1, 0, 0, 0, 0, 1, uintptr(unsafe.Pointer(&restriction)), uintptr(unsafe.Pointer(&restricted)))
	runtime.KeepAlive(restrictingSID)
	if ok == 0 {
		t.Fatalf("create restricted token: %v", callErr)
	}
	defer restricted.Close()
	var impersonation windows.Token
	if err := windows.DuplicateTokenEx(restricted, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation); err != nil {
		t.Fatal(err)
	}
	defer impersonation.Close()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.SetThreadToken(nil, impersonation); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			t.Fatalf("revert test thread token: %v", err)
		}
	}()
	var effective windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &effective); err != nil {
		t.Fatal(err)
	}
	defer effective.Close()
	isRestricted, err := effective.IsRestricted()
	if err != nil || !isRestricted {
		t.Fatalf("child thread did not acquire restricting SIDs: %v", err)
	}
	effectiveUser, err := effective.GetTokenUser()
	if err != nil || !windows.EqualSid(user.User.Sid, effectiveUser.User.Sid) {
		t.Fatalf("restricted context unexpectedly changed account identity: %v", err)
	}
	for _, test := range []struct {
		path   string
		access uint32
		deny   bool
	}{
		{os.Getenv("PICOCRYPT_CUSTODY_CONTROL"), windows.GENERIC_READ | windows.GENERIC_WRITE, false},
		{os.Getenv("PICOCRYPT_CUSTODY_STAGE"), windows.GENERIC_READ, true},
		{os.Getenv("PICOCRYPT_CUSTODY_STAGE"), windows.GENERIC_WRITE, true},
	} {
		path, err := windows.UTF16PtrFromString(test.path)
		if err != nil || test.path == "" {
			t.Fatal("missing restricted context test path")
		}
		handle, err := windows.CreateFile(path, test.access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if test.deny {
			if err == nil {
				_ = windows.CloseHandle(handle)
			}
			if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				t.Fatalf("private stage access = %v; want exact access denied, not a sharing refusal", err)
			}
		} else {
			if err != nil {
				t.Fatalf("explicitly allowed read/write control failed: %v", err)
			}
			if err := windows.CloseHandle(handle); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Log("restricted context control and denial verified")
}
