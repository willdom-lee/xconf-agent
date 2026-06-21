package driver

import (
	"testing"
)

func TestGetDriver(t *testing.T) {
	cisco, err := GetDriver("cisco", "10.0.0.1")
	if err != nil {
		t.Fatalf("failed to get cisco driver: %v", err)
	}
	if _, ok := cisco.(*CiscoDriver); !ok {
		t.Error("expected CiscoDriver type")
	}

	h3c, err := GetDriver("H3C", "10.0.0.1") // Case insensitive check
	if err != nil {
		t.Fatalf("failed to get h3c driver: %v", err)
	}
	if _, ok := h3c.(*H3CDriver); !ok {
		t.Error("expected H3CDriver type")
	}

	_, err = GetDriver("unknown", "10.0.0.1")
	if err == nil {
		t.Error("expected error for unknown driver but got nil")
	}
}

func TestCleanSwitchOutput(t *testing.T) {
	input := []byte(`
terminal length 0
show running-config
Building configuration...

Current configuration : 1234 bytes
!
interface GigabitEthernet0/1
 shutdown
!
end
Switch#`)

	expected := `Building configuration...

Current configuration : 1234 bytes
!
interface GigabitEthernet0/1
 shutdown
!
end`

	cmds := []string{"terminal length 0", "show running-config"}
	cleaned := cleanSwitchOutput(input, cmds)

	if string(cleaned) != expected {
		t.Errorf("cleanSwitchOutput failed.\nGot:\n%s\nExpected:\n%s", string(cleaned), expected)
	}
}
