package driver

import (
	"testing"
)

func TestSanitizeCisco(t *testing.T) {
	raw := `!
! Last configuration change at 09:29:43 UTC Sun Jun 21 2026 by admin
! NVRAM config last updated at 09:30:12 UTC Sun Jun 21 2026 by system
!
version 15.4
hostname Switch-Core-1
Current configuration : 1385 bytes
!
interface GigabitEthernet0/1
 shutdown
!
end`

	expected := `!
!
version 15.4
hostname Switch-Core-1
!
interface GigabitEthernet0/1
 shutdown
!
end`

	cleaned := SanitizeConfig([]byte(raw), "cisco")
	if string(cleaned) != expected {
		t.Errorf("SanitizeConfig (cisco) failed.\nGot:\n%q\nExpected:\n%q", string(cleaned), expected)
	}
}

func TestSanitizeHuawei(t *testing.T) {
	raw := `#
#Last configuration change at 2026-06-21 09:59:15+08:00
#Last commit at 2026-06-21 09:59:15+08:00
#Saved at 2026-06-21 09:59:15+08:00
#Saved Config
sysname Switch-Core-2
#
interface GigabitEthernet0/0/1
 shutdown
#`

	expected := `#
sysname Switch-Core-2
#
interface GigabitEthernet0/0/1
 shutdown
#`

	cleaned := SanitizeConfig([]byte(raw), "huawei")
	if string(cleaned) != expected {
		t.Errorf("SanitizeConfig (huawei) failed.\nGot:\n%q\nExpected:\n%q", string(cleaned), expected)
	}
}

func TestSanitizeFortinet(t *testing.T) {
	raw := `#config-version=FortiGate-60E-v6.0.4-build0286
#Serial-Number: FG60ETxxxxxx
#Last Update: Sun Jun 21 09:59:15 2026
#Last config change: Sun Jun 21 09:59:15 2026
config system global
    set hostname "FortiGate-Core"
end`

	expected := `config system global
    set hostname "FortiGate-Core"
end`

	cleaned := SanitizeConfig([]byte(raw), "fortinet")
	if string(cleaned) != expected {
		t.Errorf("SanitizeConfig (fortinet) failed.\nGot:\n%q\nExpected:\n%q", string(cleaned), expected)
	}
}

func TestSanitizeJuniper(t *testing.T) {
	raw := `## Last changed: 2026-06-21 09:59:15 UTC by admin
## Last commit: 2026-06-21 09:59:15 UTC by admin
version 18.2R1.9;
system {
    host-name MX240-Core;
}`

	expected := `version 18.2R1.9;
system {
    host-name MX240-Core;
}`

	cleaned := SanitizeConfig([]byte(raw), "juniper")
	if string(cleaned) != expected {
		t.Errorf("SanitizeConfig (juniper) failed.\nGot:\n%q\nExpected:\n%q", string(cleaned), expected)
	}
}

func TestSanitizeAruba(t *testing.T) {
	raw := `; Switch-Core-3 Configuration Editor; CX AOS-CX 10.04.0001
; Software Version CX AOS-CX 10.04.0001
Current configuration : 2580 bytes
!
hostname Aruba-CX-3`

	expected := `!
hostname Aruba-CX-3`

	cleaned := SanitizeConfig([]byte(raw), "aruba")
	if string(cleaned) != expected {
		t.Errorf("SanitizeConfig (aruba) failed.\nGot:\n%q\nExpected:\n%q", string(cleaned), expected)
	}
}
