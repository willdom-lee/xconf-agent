package driver

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"xconf-agent/config"
	"xconf-agent/logger"
)

// DeviceDriver defines the interface for fetching configurations from a network device.
type DeviceDriver interface {
	FetchConfig(dev *config.Device) ([]byte, error)
}

// GetDriver returns the appropriate driver for the given vendor
func GetDriver(vendor string, ip string) (DeviceDriver, error) {
	if ip == "127.0.0.1" && os.Getenv("XCONF_TEST_REAL_SSH") != "true" {
		return &MockDriver{}, nil
	}
	switch strings.ToLower(vendor) {
	case "cisco":
		return &CiscoDriver{}, nil
	case "huawei":
		return &HuaweiDriver{}, nil
	case "h3c":
		return &H3CDriver{}, nil
	case "ruijie":
		return &RuijieDriver{}, nil
	case "fortinet":
		return &FortinetDriver{}, nil
	case "juniper":
		return &JuniperDriver{}, nil
	case "aruba":
		return &ArubaDriver{}, nil
	case "mock":
		return &MockDriver{}, nil
	default:
		return nil, fmt.Errorf("unsupported vendor %q. Supported vendors are: cisco, huawei, h3c, ruijie, fortinet, juniper, aruba, mock", vendor)
	}
}

func resolveDataPath(relativePath string) string {
	if config.ConfigDir != "" {
		return filepath.Join(config.ConfigDir, relativePath)
	}
	exePath, err := os.Executable()
	if err != nil {
		return relativePath
	}
	return filepath.Join(filepath.Dir(exePath), relativePath)
}

// GetHostKeyCallback returns the appropriate host key callback based on device config
func GetHostKeyCallback(dev *config.Device) ssh.HostKeyCallback {
	if dev.LegacyCompatible != nil && *dev.LegacyCompatible {
		return ssh.InsecureIgnoreHostKey()
	}
	port := dev.Port
	if port == 0 {
		port = 22
	}
	return tofuHostKeyCallback(fmt.Sprintf("%s:%d", dev.IP, port))
}

var hostKeyLock sync.Mutex

func tofuHostKeyCallback(ipPort string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		hostKeyLock.Lock()
		defer hostKeyLock.Unlock()

		keyType := key.Type()
		keyBytes := key.Marshal()
		keyB64 := base64.StdEncoding.EncodeToString(keyBytes)

		hostsFilePath := resolveDataPath(filepath.Join("data", "known_hosts"))
		_ = os.MkdirAll(filepath.Dir(hostsFilePath), 0700)

		data, _ := os.ReadFile(hostsFilePath)
		lines := strings.Split(string(data), "\n")

		hostKeyMap := make(map[string]string)
		for _, line := range lines {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				hostKeyMap[parts[0]] = parts[1] + " " + parts[2]
			}
		}

		currentKey := keyType + " " + keyB64
		targetAddr := remote.String()
		if targetAddr == "" {
			targetAddr = ipPort
		}
		
		storedKey, exists := hostKeyMap[targetAddr]
		if !exists {
			storedKey, exists = hostKeyMap[hostname]
		}

		if !exists {
			f, err := os.OpenFile(hostsFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				return fmt.Errorf("failed to write known_hosts file: %w", err)
			}
			defer f.Close()
			if _, err := fmt.Fprintf(f, "%s %s %s\n", targetAddr, keyType, keyB64); err != nil {
				return fmt.Errorf("failed to persist host key for %s: %w", targetAddr, err)
			}
			logger.Info("ssh", "", "First time connecting to %s, trusted host key type %s", targetAddr, keyType)
			return nil
		}

		if storedKey != currentKey {
			return fmt.Errorf("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED for %s! Possible Man-in-the-Middle attack", targetAddr)
		}

		return nil
	}
}

// executeSSHCommands connects to a device via SSH, runs a list of commands, and returns the output of the last command
func executeSSHCommands(dev *config.Device, initCmds []string, fetchCmd string) ([]byte, error) {
	password := dev.GetResolvedPassword()
	port := dev.Port
	if port == 0 {
		port = 22
	}
	addr := fmt.Sprintf("%s:%d", dev.IP, port)

	var callback ssh.HostKeyCallback
	if dev.LegacyCompatible != nil && *dev.LegacyCompatible {
		callback = ssh.InsecureIgnoreHostKey()
	} else {
		callback = tofuHostKeyCallback(addr)
	}

	sshConfig := &ssh.ClientConfig{
		User: dev.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: callback,
		Timeout:         5 * time.Second,
		Config: ssh.Config{
			KeyExchanges: []string{
				"diffie-hellman-group1-sha1",
				"diffie-hellman-group14-sha1",
				"diffie-hellman-group14-sha256",
				"curve25519-sha256",
				"curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256",
				"ecdh-sha2-nistp384",
				"ecdh-sha2-nistp521",
			},
			Ciphers: []string{
				"aes128-ctr", "aes192-ctr", "aes256-ctr",
				"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				"aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc",
			},
		},
	}

	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SSH: %w", err)
	}
	defer client.Close()

	done := make(chan struct{})
	var sessionErr error
	var cleanedOutput []byte

	go func() {
		defer close(done)
		session, err := client.NewSession()
		if err != nil {
			sessionErr = fmt.Errorf("failed to create SSH session: %w", err)
			return
		}
		defer session.Close()

		modes := ssh.TerminalModes{
			ssh.ECHO:          0,     // disable echoing
			ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
			ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		}

		if err := session.RequestPty("vt100", 40, 80, modes); err != nil {
			sessionErr = fmt.Errorf("failed to request pty: %w", err)
			return
		}

		in, err := session.StdinPipe()
		if err != nil {
			sessionErr = fmt.Errorf("failed to get stdin pipe: %w", err)
			return
		}

		out, err := session.StdoutPipe()
		if err != nil {
			sessionErr = fmt.Errorf("failed to get stdout pipe: %w", err)
			return
		}

		if err := session.Shell(); err != nil {
			sessionErr = fmt.Errorf("failed to start shell: %w", err)
			return
		}

		go func() {
			defer in.Close()
			for _, cmd := range initCmds {
				_, _ = fmt.Fprintln(in, cmd)
				time.Sleep(100 * time.Millisecond)
			}
			_, _ = fmt.Fprintln(in, fetchCmd)
			time.Sleep(200 * time.Millisecond)
			_, _ = fmt.Fprintln(in, "exit")
		}()

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, out)

		_ = session.Wait()
		cleanedOutput = cleanSwitchOutput(buf.Bytes(), append(initCmds, fetchCmd))
	}()

	select {
	case <-done:
		return cleanedOutput, sessionErr
	case <-time.After(30 * time.Second): // 30s timeout
		client.Close()
		return nil, fmt.Errorf("SSH operation timed out after 30s")
	}
}

// cleanSwitchOutput removes command echoes, terminal banners, and trailing prompts from the output
func cleanSwitchOutput(output []byte, cmds []string) []byte {
	lines := strings.Split(string(output), "\n")
	var cleaned []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.ReplaceAll(trimmed, "\r", "")

		// Skip echo lines
		isEcho := false
		for _, cmd := range cmds {
			if strings.Contains(trimmed, cmd) {
				isEcho = true
				break
			}
		}

		// Skip prompt lines (lines ending in '#' or '>')
		if strings.HasSuffix(trimmed, "#") || strings.HasSuffix(trimmed, ">") {
			continue
		}

		if isEcho {
			continue
		}

		cleaned = append(cleaned, line)
	}

	return []byte(strings.TrimSpace(strings.Join(cleaned, "\n")))
}

const (
	stateNormal = iota
	stateIAC
	stateWill
	stateWont
	stateDo
	stateDont
	stateSB
	stateSBIAC
)

// TelnetConn wraps a TCP connection and filters/negotiates Telnet options
type TelnetConn struct {
	conn  net.Conn
	state int
	buf   []byte
}

func (tc *TelnetConn) Read(p []byte) (int, error) {
	for {
		if len(tc.buf) > 0 {
			n := copy(p, tc.buf)
			tc.buf = tc.buf[n:]
			return n, nil
		}

		var raw [4096]byte
		n, err := tc.conn.Read(raw[:])
		if err != nil {
			return 0, err
		}

		for i := 0; i < n; i++ {
			b := raw[i]
			switch tc.state {
			case stateNormal:
				if b == 255 {
					tc.state = stateIAC
				} else {
					tc.buf = append(tc.buf, b)
				}
			case stateIAC:
				switch b {
				case 251: // WILL
					tc.state = stateWill
				case 252: // WONT
					tc.state = stateWont
				case 253: // DO
					tc.state = stateDo
				case 254: // DONT
					tc.state = stateDont
				case 250: // SB
					tc.state = stateSB
				case 255: // Escaped 255
					tc.buf = append(tc.buf, 255)
					tc.state = stateNormal
				default:
					tc.state = stateNormal
				}
			case stateWill:
				_, _ = tc.conn.Write([]byte{255, 254, b})
				tc.state = stateNormal
			case stateWont:
				_, _ = tc.conn.Write([]byte{255, 254, b})
				tc.state = stateNormal
			case stateDo:
				_, _ = tc.conn.Write([]byte{255, 252, b})
				tc.state = stateNormal
			case stateDont:
				_, _ = tc.conn.Write([]byte{255, 252, b})
				tc.state = stateNormal
			case stateSB:
				if b == 255 {
					tc.state = stateSBIAC
				}
			case stateSBIAC:
				if b == 240 {
					tc.state = stateNormal
				} else {
					tc.state = stateSB
				}
			}
		}
	}
}

func (tc *TelnetConn) SetReadDeadline(t time.Time) error {
	return tc.conn.SetReadDeadline(t)
}


func readUntil(tc *TelnetConn, delimiters []string, timeout time.Duration) (string, string, error) {
	var accumulated []byte
	var buf [512]byte
	start := time.Now()

	for {
		if time.Since(start) > timeout {
			return string(accumulated), "", fmt.Errorf("timeout waiting for delimiters: %v", delimiters)
		}

		_ = tc.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := tc.Read(buf[:])
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if time.Since(start) > timeout {
					return string(accumulated), "", fmt.Errorf("timeout waiting for delimiters (total): %v", delimiters)
				}
				continue
			}
			return string(accumulated), "", err
		}

		accumulated = append(accumulated, buf[:n]...)
		str := string(accumulated)

		trimmed := strings.TrimRight(str, " \t\r\n")
		for _, delim := range delimiters {
			if strings.HasSuffix(trimmed, delim) {
				return str, delim, nil
			}
		}
	}
}

func executeTelnetCommands(dev *config.Device, initCmds []string, fetchCmd string) ([]byte, error) {
	password := dev.GetResolvedPassword()
	port := dev.Port
	if port == 0 {
		port = 23
	}
	addr := net.JoinHostPort(dev.IP, fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to dial Telnet: %w", err)
	}
	defer conn.Close()

	tc := &TelnetConn{conn: conn}

	// 1. Wait for login / password prompts
	loginDelims := []string{"Username:", "username:", "login:", "Login:", "Password:", "password:", ">", "#", "<", "]"}
	out, matched, err := readUntil(tc, loginDelims, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed waiting for login prompt: %w", err)
	}

	if strings.Contains(strings.ToLower(matched), "user") || strings.Contains(strings.ToLower(matched), "login") {
		_, err = fmt.Fprint(tc.conn, dev.Username+"\r\n")
		if err != nil {
			return nil, fmt.Errorf("failed sending username: %w", err)
		}
		_, _, err = readUntil(tc, []string{"Password:", "password:"}, 5*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed waiting for password prompt: %w", err)
		}
		_, err = fmt.Fprint(tc.conn, password+"\r\n")
		if err != nil {
			return nil, fmt.Errorf("failed sending password: %w", err)
		}
	} else if strings.Contains(strings.ToLower(matched), "password") {
		_, err = fmt.Fprint(tc.conn, password+"\r\n")
		if err != nil {
			return nil, fmt.Errorf("failed sending password: %w", err)
		}
	}

	// 2. Wait for shell prompt
	shellDelims := []string{">", "#", "<", "]"}
	out, matched, err = readUntil(tc, shellDelims, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed waiting for post-login prompt: %w", err)
	}

	// Cisco Privilege Elevation
	if matched == ">" && strings.ToLower(dev.Vendor) == "cisco" {
		_, err = fmt.Fprint(tc.conn, "enable\r\n")
		if err != nil {
			return nil, fmt.Errorf("failed sending enable command: %w", err)
		}
		out, matched, err = readUntil(tc, []string{"Password:", "password:", "#"}, 5*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed waiting for enable password prompt: %w", err)
		}
		if matched != "#" {
			_, err = fmt.Fprint(tc.conn, password+"\r\n")
			if err != nil {
				return nil, fmt.Errorf("failed sending enable password: %w", err)
			}
			out, matched, err = readUntil(tc, []string{"#"}, 5*time.Second)
			if err != nil {
				return nil, fmt.Errorf("failed waiting for privileged prompt #: %w", err)
			}
		}
	}

	// Detect shell prompt dynamically from the end of the last read output
	prompt := "#"
	lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
	if len(lines) > 0 {
		lastLine := strings.TrimSpace(lines[len(lines)-1])
		if lastLine != "" {
			prompt = lastLine
		}
	}

	// Execute init commands
	for _, cmd := range initCmds {
		_, err = fmt.Fprint(tc.conn, cmd+"\r\n")
		if err != nil {
			return nil, fmt.Errorf("failed sending init command %q: %w", cmd, err)
		}
		_, _, err = readUntil(tc, []string{prompt}, 5*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed waiting for prompt after init command %q: %w", cmd, err)
		}
	}

	// If fetchCmd is empty, we just return nil, nil (used for verification in check)
	if fetchCmd == "" {
		_, _ = fmt.Fprint(tc.conn, "exit\r\n")
		return nil, nil
	}

	// Execute config retrieval command
	_, err = fmt.Fprint(tc.conn, fetchCmd+"\r\n")
	if err != nil {
		return nil, fmt.Errorf("failed sending fetch command %q: %w", fetchCmd, err)
	}

	fetchOut, _, err := readUntil(tc, []string{prompt}, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed waiting for configuration output: %w", err)
	}

	_, _ = fmt.Fprint(tc.conn, "exit\r\n")

	return cleanSwitchOutput([]byte(fetchOut), append(initCmds, fetchCmd)), nil
}
