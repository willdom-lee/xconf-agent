package driver

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"xconf-agent/config"
)

func TestTelnetNegotiationAndLogin(t *testing.T) {
	// Start local TCP mock Telnet server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock TCP server: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	portVal := 23
	parts := strings.Split(addr, ":")
	if len(parts) == 2 {
		var p int
		_, err := fmt.Sscanf(parts[1], "%d", &p)
		if err == nil {
			portVal = p
		}
	}

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// 1. Send some Telnet Option Negotiations
		// IAC DO (255 253) Option 3 (transmit binary)
		// IAC WILL (255 251) Option 1 (echo)
		_, _ = conn.Write([]byte{255, 253, 3, 255, 251, 1})

		// Read responses from client. Since client passive-rejects:
		// IAC DO 3 -> IAC WONT 3 (255 252 3)
		// IAC WILL 1 -> IAC DONT 1 (255 254 1)
		buf := make([]byte, 6)
		_, _ = conn.Read(buf)

		// 2. Send Username prompt
		_, _ = conn.Write([]byte("Username: "))

		// Read username
		userBuf := make([]byte, 128)
		n, _ := conn.Read(userBuf)
		_ = n

		// 3. Send Password prompt
		_, _ = conn.Write([]byte("Password: "))

		// Read password
		passBuf := make([]byte, 128)
		n, _ = conn.Read(passBuf)
		_ = n

		// 4. Send shell prompt
		_, _ = conn.Write([]byte("Switch#"))

		// Read command
		cmdBuf := make([]byte, 128)
		n, _ = conn.Read(cmdBuf)
		_ = n

		// Reply to command
		_, _ = conn.Write([]byte("terminal length 0\r\nSwitch#"))

		// Read next command
		n, _ = conn.Read(cmdBuf)
		_ = n

		// Send configuration
		_, _ = conn.Write([]byte("show running-config\r\nBuilding configuration...\r\nhostname Switch\r\ninterface Vlan1\r\nSwitch#"))

		// Read exit
		n, _ = conn.Read(cmdBuf)
		_ = n
	}()

	dev := &config.Device{
		ID:       "test-id",
		Name:     "Test Cisco",
		IP:       "127.0.0.1",
		Port:     portVal,
		Vendor:   "cisco",
		Username: "admin",
		Password: "secret",
		Protocol: "telnet",
	}

	initCmds := []string{"terminal length 0"}
	fetchCmd := "show running-config"

	output, err := executeTelnetCommands(dev, initCmds, fetchCmd)
	if err != nil {
		t.Fatalf("executeTelnetCommands failed: %v", err)
	}

	outputStr := strings.ReplaceAll(string(output), "\r\n", "\n")
	expected := "Building configuration...\nhostname Switch\ninterface Vlan1"
	if outputStr != expected {
		t.Errorf("expected output:\n%q\ngot:\n%q", expected, outputStr)
	}
}
