//go:build windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// HardenConfigPermissions hardens the configuration file permissions on Windows by:
// 1. Stripping inherited DACLs (disabling inheritance).
// 2. Granting GENERIC_ALL (full control) only to the current user (owner), Local SYSTEM, and Builtin Administrators.
func HardenConfigPermissions(path string) error {
	// 1. Get the current process user's SID (owner SID)
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("failed to open current process token: %w", err)
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("failed to get token user: %w", err)
	}
	ownerSID := tokenUser.User.Sid

	// 2. Create SIDs for SYSTEM and Administrators
	var systemSID *windows.SID
	err = windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		1,
		windows.SECURITY_LOCAL_SYSTEM_RID,
		0, 0, 0, 0, 0, 0, 0,
		&systemSID,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize SYSTEM SID: %w", err)
	}
	defer windows.FreeSid(systemSID)

	var adminSID *windows.SID
	err = windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&adminSID,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize Administrators SID: %w", err)
	}
	defer windows.FreeSid(adminSID)

	// 3. Build EXPLICIT_ACCESS structures
	explicitAccess := make([]windows.EXPLICIT_ACCESS, 3)

	// Current user full control
	explicitAccess[0] = windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(ownerSID),
		},
	}

	// Local SYSTEM full control
	explicitAccess[1] = windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(systemSID),
		},
	}

	// Administrators full control
	explicitAccess[2] = windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(adminSID),
		},
	}

	// 4. Create new DACL using ACLFromEntries
	acl, err := windows.ACLFromEntries(explicitAccess, nil)
	if err != nil {
		return fmt.Errorf("failed to create DACL: %w", err)
	}

	// 5. Apply security info to the file:
	// Set the DACL on the file and flag it with PROTECTED_DACL_SECURITY_INFORMATION to disable inheritance.
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, // Owner SID (keep current)
		nil, // Group SID (keep current)
		acl,
		nil, // SACL
	)
	if err != nil {
		return fmt.Errorf("failed to set named security info (SetNamedSecurityInfo): %w", err)
	}

	return nil
}

// GetDefaultConfigPath returns the robust default configuration path on Windows.
// It defaults to the executable's directory, unless the executable resides inside System32/Windows directory,
// in which case it falls back to C:\ProgramData\xconf-agent\config.yaml to prevent folder permissions and system pollution issues.
func GetDefaultConfigPath() string {
	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		lowerDir := strings.ToLower(exeDir)
		if strings.Contains(lowerDir, `\system32`) || strings.Contains(lowerDir, `\windows`) {
			programData := os.Getenv("ProgramData")
			if programData != "" {
				return filepath.Join(programData, "xconf-agent", "config.yaml")
			}
			return `C:\ProgramData\xconf-agent\config.yaml`
		}
		return filepath.Join(exeDir, "config.yaml")
	}
	return "config.yaml"
}
