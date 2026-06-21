package driver

import (
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"xconf-agent/config"
)

var (
	// Strong algorithms for secure default mode
	StrongKeyExchanges = []string{
		"curve25519-sha256",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
	}

	StrongCiphers = []string{
		"aes128-gcm@openssh.com",
		"aes256-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"aes128-ctr",
		"aes192-ctr",
		"aes256-ctr",
	}

	// Legacy compatible algorithms
	LegacyKeyExchanges = []string{
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group14-sha256",
		"curve25519-sha256",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
	}

	LegacyCiphers = []string{
		"aes128-ctr",
		"aes192-ctr",
		"aes256-ctr",
		"aes128-gcm@openssh.com",
		"aes256-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"aes128-cbc",
		"aes192-cbc",
		"aes256-cbc",
		"3des-cbc",
	}
)

type deadliner interface {
	SetReadDeadline(t time.Time) error
}

type deadlineReader struct {
	reader io.Reader
	conn   net.Conn
}

func (dr *deadlineReader) Read(p []byte) (int, error) {
	return dr.reader.Read(p)
}

func (dr *deadlineReader) SetReadDeadline(t time.Time) error {
	return dr.conn.SetReadDeadline(t)
}

func readUntilRegex(reader io.Reader, patterns []*regexp.Regexp, timeout time.Duration) (string, int, string, error) {
	var accumulated []byte
	start := time.Now()

	for {
		remaining := timeout - time.Since(start)
		if remaining <= 0 {
			return string(accumulated), -1, "", fmt.Errorf("timeout waiting for patterns after %v", timeout)
		}

		if dl, ok := reader.(deadliner); ok {
			_ = dl.SetReadDeadline(time.Now().Add(remaining))
		}

		buf := make([]byte, 1024)
		n, err := reader.Read(buf)
		if n > 0 {
			accumulated = append(accumulated, buf[:n]...)
			currentStr := string(accumulated)

			// Trim trailing spaces/newlines to reliably match prompts at the end of the buffer
			trimmed := strings.TrimRight(currentStr, " \t\r\n")

			for idx, re := range patterns {
				matches := re.FindAllStringIndex(trimmed, -1)
				if len(matches) > 0 {
					lastMatch := matches[len(matches)-1]
					if lastMatch[1] == len(trimmed) {
						// Match is at the very end of the output, meaning the device is waiting for input
						matchedStr := trimmed[lastMatch[0]:lastMatch[1]]
						if dl, ok := reader.(deadliner); ok {
							_ = dl.SetReadDeadline(time.Time{})
						}
						return currentStr, idx, matchedStr, nil
					}
				}
			}
		}

		if err != nil {
			if dl, ok := reader.(deadliner); ok {
				_ = dl.SetReadDeadline(time.Time{})
			}
			if time.Since(start) >= timeout {
				return string(accumulated), -1, "", fmt.Errorf("timeout waiting for patterns after %v", timeout)
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return string(accumulated), -1, "", fmt.Errorf("timeout waiting for patterns after %v", timeout)
			}
			return string(accumulated), -1, "", err
		}
	}
}

// FetchDeviceConfig is the main entry point to retrieve configuration based on vendor model
func FetchDeviceConfig(dev *config.Device) ([]byte, error) {
	vendor := strings.ToLower(dev.Vendor)
	model, err := GetDeviceModel(vendor)
	if err != nil {
		return nil, fmt.Errorf("failed to load device model for vendor %q: %w", dev.Vendor, err)
	}

	protocol := strings.ToLower(dev.Protocol)
	if protocol == "" {
		protocol = "ssh"
	}

	var rawConfig []byte
	if protocol == "ssh" {
		rawConfig, err = executeSSHExpect(dev, model)
	} else if protocol == "telnet" {
		rawConfig, err = executeTelnetExpect(dev, model)
	} else {
		return nil, fmt.Errorf("unsupported protocol %q", dev.Protocol)
	}

	if err != nil {
		return nil, err
	}

	// Apply RE2 regex configuration sanitization to strip clock comments, NVRAM noise, file size, etc.
	sanitized := SanitizeConfig(rawConfig, dev.Vendor)
	return sanitized, nil
}

func executeSSHExpect(dev *config.Device, model *DeviceModel) ([]byte, error) {
	password := dev.GetResolvedPassword()
	port := dev.Port
	if port == 0 {
		port = 22
	}
	addr := fmt.Sprintf("%s:%d", dev.IP, port)

	isLegacy := dev.LegacyCompatible != nil && *dev.LegacyCompatible

	var callback ssh.HostKeyCallback
	var kexs, ciphers []string

	if isLegacy {
		callback = ssh.InsecureIgnoreHostKey()
		kexs = LegacyKeyExchanges
		ciphers = LegacyCiphers
	} else {
		callback = tofuHostKeyCallback(addr)
		kexs = StrongKeyExchanges
		ciphers = StrongCiphers
	}

	sshConfig := &ssh.ClientConfig{
		User: dev.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: callback,
		Timeout:         10 * time.Second,
		Config: ssh.Config{
			KeyExchanges: kexs,
			Ciphers:      ciphers,
		},
	}

	conn, err := net.DialTimeout("tcp", addr, sshConfig.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SSH: %w", err)
	}
	defer conn.Close()

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH client conn: %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("vt100", 80, 40, modes); err != nil {
		return nil, fmt.Errorf("failed to request pty: %w", err)
	}

	in, err := session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdin pipe: %w", err)
	}
	defer in.Close()

	out, err := session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	dr := &deadlineReader{
		reader: out,
		conn:   conn,
	}

	if err := session.Shell(); err != nil {
		return nil, fmt.Errorf("failed to start shell: %w", err)
	}

	// Dynamic interactive state machine using expectation matching
	rePrompt, err := regexp.Compile(model.PromptRegex)
	if err != nil {
		return nil, fmt.Errorf("invalid prompt regex %q: %w", model.PromptRegex, err)
	}

	reUser := regexp.MustCompile(`(?i)(username|login):`)
	rePass := regexp.MustCompile(`(?i)password:`)

	// 1. Wait for initial prompt (either user, pass or shell prompt)
	patterns := []*regexp.Regexp{reUser, rePass, rePrompt}
	output, matchedIdx, _, err := readUntilRegex(dr, patterns, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed during initial shell prompt check: %w", err)
	}

	// If prompted for login credentials (some SSH servers or jumpboxes might ask again)
	if matchedIdx == 0 { // Username
		_, _ = fmt.Fprint(in, dev.Username+"\n")
		output, matchedIdx, _, err = readUntilRegex(dr, []*regexp.Regexp{rePass, rePrompt}, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed waiting for password prompt: %w", err)
		}
		if matchedIdx == 0 { // Password
			_, _ = fmt.Fprint(in, password+"\n")
			_, _, _, err = readUntilRegex(dr, []*regexp.Regexp{rePrompt}, 10*time.Second)
			if err != nil {
				return nil, fmt.Errorf("failed waiting for shell prompt after password: %w", err)
			}
		}
	} else if matchedIdx == 1 { // Password
		_, _ = fmt.Fprint(in, password+"\n")
		_, _, _, err = readUntilRegex(dr, []*regexp.Regexp{rePrompt}, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed waiting for shell prompt after password: %w", err)
		}
	}

	// 2. Send initialization commands (e.g. screen length disable / terminal length 0)
	for _, cmd := range model.InitCommands {
		_, _ = fmt.Fprint(in, cmd+"\n")
		_, _, _, err = readUntilRegex(dr, []*regexp.Regexp{rePrompt}, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed during init command %q: %w", cmd, err)
		}
	}

	// 3. Send backup command
	_, _ = fmt.Fprint(in, model.BackupCommand+"\n")
	output, _, _, err = readUntilRegex(dr, []*regexp.Regexp{rePrompt}, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed during backup command %q: %w", model.BackupCommand, err)
	}

	// 4. Clean exit
	_, _ = fmt.Fprint(in, "exit\n")

	// Filter echoes and prompt headers out of config
	allCmds := append(model.InitCommands, model.BackupCommand)
	return cleanSwitchOutput([]byte(output), allCmds), nil
}

func executeTelnetExpect(dev *config.Device, model *DeviceModel) ([]byte, error) {
	password := dev.GetResolvedPassword()
	port := dev.Port
	if port == 0 {
		port = 23
	}
	addr := net.JoinHostPort(dev.IP, fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to dial Telnet: %w", err)
	}
	defer conn.Close()

	tc := &TelnetConn{conn: conn}

	rePrompt, err := regexp.Compile(model.PromptRegex)
	if err != nil {
		return nil, fmt.Errorf("invalid prompt regex %q: %w", model.PromptRegex, err)
	}

	reUser := regexp.MustCompile(`(?i)(username|login):`)
	rePass := regexp.MustCompile(`(?i)password:`)
	reCiscoUserPrompt := regexp.MustCompile(`(?i)user verification`)

	// 1. Wait for username, password or shell prompts
	patterns := []*regexp.Regexp{reUser, rePass, rePrompt, reCiscoUserPrompt}
	output, matchedIdx, _, err := readUntilRegex(tc, patterns, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed waiting for initial login/prompt: %w", err)
	}

	// Handle username/login
	if matchedIdx == 0 || matchedIdx == 3 {
		_, err = fmt.Fprint(tc.conn, dev.Username+"\r\n")
		if err != nil {
			return nil, fmt.Errorf("failed sending username: %w", err)
		}
		output, matchedIdx, _, err = readUntilRegex(tc, []*regexp.Regexp{rePass, rePrompt}, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed waiting for password prompt: %w", err)
		}
		if matchedIdx == 0 {
			_, err = fmt.Fprint(tc.conn, password+"\r\n")
			if err != nil {
				return nil, fmt.Errorf("failed sending password: %w", err)
			}
			output, _, _, err = readUntilRegex(tc, []*regexp.Regexp{rePrompt}, 10*time.Second)
			if err != nil {
				return nil, fmt.Errorf("failed waiting for shell prompt: %w", err)
			}
		}
	} else if matchedIdx == 1 { // Password only
		_, err = fmt.Fprint(tc.conn, password+"\r\n")
		if err != nil {
			return nil, fmt.Errorf("failed sending password: %w", err)
		}
		output, _, _, err = readUntilRegex(tc, []*regexp.Regexp{rePrompt}, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed waiting for shell prompt: %w", err)
		}
	}

	// Cisco Privilege Elevation if prompt ends in '>'
	trimmed := strings.TrimRight(output, " \t\r\n")
	if strings.HasSuffix(trimmed, ">") && strings.ToLower(dev.Vendor) == "cisco" {
		_, err = fmt.Fprint(tc.conn, "enable\r\n")
		if err != nil {
			return nil, fmt.Errorf("failed sending enable: %w", err)
		}
		output, matchedIdx, _, err = readUntilRegex(tc, []*regexp.Regexp{rePass, rePrompt}, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed waiting for enable password: %w", err)
		}
		if matchedIdx == 0 {
			_, err = fmt.Fprint(tc.conn, password+"\r\n")
			if err != nil {
				return nil, fmt.Errorf("failed sending enable password: %w", err)
			}
			_, _, _, err = readUntilRegex(tc, []*regexp.Regexp{rePrompt}, 10*time.Second)
			if err != nil {
				return nil, fmt.Errorf("failed waiting for privilege shell prompt: %w", err)
			}
		}
	}

	// 2. Send initialization commands
	for _, cmd := range model.InitCommands {
		_, err = fmt.Fprint(tc.conn, cmd+"\r\n")
		if err != nil {
			return nil, fmt.Errorf("failed sending init command %q: %w", cmd, err)
		}
		_, _, _, err = readUntilRegex(tc, []*regexp.Regexp{rePrompt}, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed waiting for prompt after %q: %w", cmd, err)
		}
	}

	// 3. Send backup command
	_, err = fmt.Fprint(tc.conn, model.BackupCommand+"\r\n")
	if err != nil {
		return nil, fmt.Errorf("failed sending backup command: %w", err)
	}

	fetchOut, _, _, err := readUntilRegex(tc, []*regexp.Regexp{rePrompt}, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed waiting for config output: %w", err)
	}

	// 4. Clean exit
	_, _ = fmt.Fprint(tc.conn, "exit\r\n")

	allCmds := append(model.InitCommands, model.BackupCommand)
	return cleanSwitchOutput([]byte(fetchOut), allCmds), nil
}
