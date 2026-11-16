package distmeta

import (
	"regexp"
	"strings"
	"testing"
)

// This is an installer publication-policy check, not native Windows ACL coverage.
// The native principal/access tests live in dist/windows/tests/authority.ps1.
func TestWindowsInstallerChecksAuthorityBeforePublication(t *testing.T) {
	script := string(mustReadFile(t, "dist/windows/installer.nsi"))
	core := regexp.MustCompile(`(?ms)^Section "-Picocrypt-NG \(required\)" SecCore.*?^SectionEnd`).FindString(script)
	guard := strings.Index(core, "Call pcng.RequireProtectedInstallDir")
	firstWrite := strings.Index(core, `SetOutPath "$INSTDIR"`)
	if guard < 0 || firstWrite < 0 || guard > firstWrite {
		t.Fatal("final INSTDIR authority must be checked before the first elevated destination write, including /D and stored paths")
	}
	if !strings.Contains(script, `!include "${__FILEDIR__}\install-authority.nsh"`) {
		t.Fatal("installer must embed the reviewed stock Win32 authority implementation")
	}
	if strings.Contains(script, "ExecWait") || strings.Contains(script, "AccessControl::") {
		t.Fatal("setup must not execute an old uninstaller or repair arbitrary destination ACLs with an external plugin")
	}
}
