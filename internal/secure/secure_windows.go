//go:build windows

package secure

import (
	"os"

	"golang.org/x/sys/windows"
)

// P = protected (no inheritance from parent); OICI = inherit to children.
// SY = LocalSystem, BA = BUILTIN\Administrators; FA = full access.
const sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

func restrictDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}
