package driver

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"xconf-agent/config"
	"xconf-agent/crypto"
)

// generateSigner generates a temporary RSA private key for the mock SSH server
func generateSigner() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return ssh.ParsePrivateKey(pemBytes)
}

func startMockSSHServer(t *testing.T, mockConfigs map[string]string) (string, func()) {
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == "secret" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected")
		},
	}

	signer, err := generateSigner()
	if err != nil {
		t.Fatalf("Failed to generate host key: %v", err)
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	addr := listener.Addr().String()
	stopChan := make(chan struct{})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-stopChan:
					return
				default:
					continue
				}
			}

			go func(c net.Conn) {
				defer c.Close()
				sshConn, chans, reqs, err := ssh.NewServerConn(c, config)
				if err != nil {
					return
				}
				defer sshConn.Close()

				go ssh.DiscardRequests(reqs)

				for newChannel := range chans {
					if newChannel.ChannelType() != "session" {
						newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}

					channel, requests, err := newChannel.Accept()
					if err != nil {
						return
					}

					go func(ch ssh.Channel, user string, reqs <-chan *ssh.Request) {
						defer ch.Close()
						for req := range reqs {
							switch req.Type {
							case "pty-req":
								_ = req.Reply(true, nil)
							case "shell":
								_ = req.Reply(true, nil)
								go handleShellSession(ch, user, mockConfigs)
							default:
								_ = req.Reply(false, nil)
							}
						}
					}(channel, sshConn.User(), requests)
				}
			}(conn)
		}
	}()

	closeCallback := func() {
		close(stopChan)
		_ = listener.Close()
	}

	return addr, closeCallback
}

func handleShellSession(ch ssh.Channel, user string, mockConfigs map[string]string) {
	defer ch.Close()
	
	// Send initial prompt based on user to match expect engine prompts
	if user == "cisco" || user == "ruijie" || user == "aruba" {
		_, _ = ch.Write([]byte("Switch#\r\n"))
	} else if user == "h3c" || user == "huawei" {
		_, _ = ch.Write([]byte("<Switch>\r\n"))
	} else if user == "fortinet" {
		_, _ = ch.Write([]byte("FortiGate#\r\n"))
	} else if user == "juniper" {
		_, _ = ch.Write([]byte("user@router>\r\n"))
	} else {
		_, _ = ch.Write([]byte("Switch#\r\n<H3C>\r\n"))
	}

	buf := make([]byte, 1024)
	var cmdBuffer strings.Builder

	for {
		n, err := ch.Read(buf)
		if err != nil {
			return
		}
		cmdBuffer.Write(buf[:n])
		input := cmdBuffer.String()

		if strings.Contains(input, "\n") || strings.Contains(input, "\r") {
			cmd := strings.TrimSpace(input)
			cmd = strings.ReplaceAll(cmd, "\r", "")
			cmd = strings.ReplaceAll(cmd, "\n", "")
			cmdBuffer.Reset()

			if cmd == "exit" {
				_, _ = ch.Write([]byte("Goodbye!\r\n"))
				return
			}

			// Respond based on command type and user
			if cmd == "show running-config" || cmd == "display current-configuration" || cmd == "show" || cmd == "show configuration" || cmd == "show full-configuration" {
				cfgContent := mockConfigs[user]
				var prompt string
				if user == "cisco" || user == "ruijie" || user == "aruba" {
					prompt = "\r\nSwitch#"
				} else if user == "h3c" || user == "huawei" {
					prompt = "\r\n<Switch>"
				} else if user == "fortinet" {
					prompt = "\r\nFortiGate#"
				} else if user == "juniper" {
					prompt = "\r\nuser@router>"
				}
				_, _ = ch.Write([]byte(cfgContent + prompt))
			} else {
				var prompt string
				if user == "cisco" || user == "ruijie" || user == "aruba" {
					prompt = "Switch#"
				} else if user == "h3c" || user == "huawei" {
					prompt = "<Switch>"
				} else if user == "fortinet" {
					prompt = "FortiGate#"
				} else if user == "juniper" {
					prompt = "user@router>"
				}
				_, _ = ch.Write([]byte("\r\n" + prompt))
			}
		}
	}
}

func TestEdgeBackupPipelineWithSimulator(t *testing.T) {
	mockConfigs := map[string]string{
		"cisco": `!
Building configuration...
Current configuration : 100 bytes
!
username admin privilege 15 secret 5 $1$mERr$mockciscopass
snmp-server community read simple mock_community
interface GigabitEthernet0/1
 shutdown
!
end`,
		"h3c": `#
version 7.1.070
#
local-user admin class manage
 password simple mock_h3c_pass
 service-type ssh
#
interface GigabitEthernet1/0/1
 port link-mode route
#
return`,
		"huawei": `#
version 8.0
#
local-user admin class manage
 password simple mock_huawei_pass
 service-type ssh
#
interface GigabitEthernet2/0/1
 port link-mode route
#
return`,
		"ruijie": `!
Building configuration...
!
username admin privilege 15 secret 5 $1$mERr$mockruijiepass
interface GigabitEthernet0/2
 shutdown
!
end`,
		"fortinet": `config system global
    set hostname FortiGate
end
config system admin
    edit "admin"
        password simple mock_fortinet_pass
    next
end`,
		"juniper": `system {
    host-name JuniperRouter;
    root-authentication {
        password simple "mock_juniper_pass";
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}`,
		"aruba": `hostname "ArubaSwitch"
password simple "mock_aruba_pass"
interface 1
   no shutdown
exit`,
	}

	t.Setenv("XCONF_TEST_REAL_SSH", "true")

	addr, closeServer := startMockSSHServer(t, mockConfigs)
	defer closeServer()

	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		t.Fatalf("Invalid address format: %s", addr)
	}
	ip := parts[0]
	port := 0
	_, _ = fmt.Sscanf(parts[1], "%d", &port)

	cases := []struct {
		vendor           string
		username         string
		expectedInConfig string
		maskedTarget     string
		unmaskedSecret   string
	}{
		{
			vendor:           "cisco",
			username:         "cisco",
			expectedInConfig: "interface GigabitEthernet0/1",
			maskedTarget:     "secret 5 [MASKED]",
			unmaskedSecret:   "$1$mERr$mockciscopass",
		},
		{
			vendor:           "h3c",
			username:         "h3c",
			expectedInConfig: "interface GigabitEthernet1/0/1",
			maskedTarget:     "password simple [MASKED]",
			unmaskedSecret:   "mock_h3c_pass",
		},
		{
			vendor:           "huawei",
			username:         "huawei",
			expectedInConfig: "interface GigabitEthernet2/0/1",
			maskedTarget:     "password simple [MASKED]",
			unmaskedSecret:   "mock_huawei_pass",
		},
		{
			vendor:           "ruijie",
			username:         "ruijie",
			expectedInConfig: "interface GigabitEthernet0/2",
			maskedTarget:     "secret 5 [MASKED]",
			unmaskedSecret:   "$1$mERr$mockruijiepass",
		},
		{
			vendor:           "fortinet",
			username:         "fortinet",
			expectedInConfig: "set hostname FortiGate",
			maskedTarget:     "password simple [MASKED]",
			unmaskedSecret:   "mock_fortinet_pass",
		},
		{
			vendor:           "juniper",
			username:         "juniper",
			expectedInConfig: "JuniperRouter",
			maskedTarget:     "password simple [MASKED]",
			unmaskedSecret:   "mock_juniper_pass",
		},
		{
			vendor:           "aruba",
			username:         "aruba",
			expectedInConfig: "ArubaSwitch",
			maskedTarget:     "password simple [MASKED]",
			unmaskedSecret:   "mock_aruba_pass",
		},
	}

	for _, tc := range cases {
		t.Run("Test "+tc.vendor+" Backup Pipeline", func(t *testing.T) {
			dev := &config.Device{
				ID:       "dev_" + tc.vendor + "_test",
				Name:     "Test-" + tc.vendor + "-Device",
				IP:       ip,
				Port:     port,
				Vendor:   tc.vendor,
				Username: tc.username,
				Password: "env:TEST_PASS_ENV",
			}
			t.Setenv("TEST_PASS_ENV", "secret")

			drv, err := GetDriver(dev.Vendor, dev.IP)
			if err != nil {
				t.Fatalf("failed to get %s driver: %v", tc.vendor, err)
			}

			plaintext, err := drv.FetchConfig(dev)
			if err != nil {
				t.Fatalf("%s fetch failed: %v", tc.vendor, err)
			}

			if !strings.Contains(string(plaintext), tc.expectedInConfig) {
				t.Errorf("Plaintext config does not contain expected string %q. Got:\n%s", tc.expectedInConfig, string(plaintext))
			}

			agentKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			keyBytes, err := config.ValidateKey(agentKey)
			if err != nil {
				t.Fatalf("invalid agent key: %v", err)
			}

			encrypted, err := crypto.EncryptConfig(plaintext, keyBytes)
			if err != nil {
				t.Fatalf("encryption failed: %v", err)
			}

			decrypted, err := crypto.DecryptConfig(encrypted, keyBytes)
			if err != nil {
				t.Fatalf("decryption failed: %v", err)
			}

			if string(decrypted) != string(plaintext) {
				t.Errorf("Decrypted config does not match original plaintext")
			}

			maskReader := crypto.NewMaskingReader(bytes.NewReader(plaintext))
			var gzipBuf bytes.Buffer
			gzipWriter := gzip.NewWriter(&gzipBuf)
			_, err = io.Copy(gzipWriter, maskReader)
			if err != nil {
				t.Fatalf("masking failed: %v", err)
			}
			gzipWriter.Close()

			gzipReader, err := gzip.NewReader(&gzipBuf)
			if err != nil {
				t.Fatalf("failed to create gzip reader: %v", err)
			}
			defer gzipReader.Close()
			var decompressed bytes.Buffer
			_, err = io.Copy(&decompressed, gzipReader)
			if err != nil {
				t.Fatalf("decompression failed: %v", err)
			}

			maskedText := decompressed.String()

			if strings.Contains(maskedText, tc.unmaskedSecret) {
				t.Errorf("Secret %q was NOT masked in %s config. Got:\n%s", tc.unmaskedSecret, tc.vendor, maskedText)
			}
			if !strings.Contains(maskedText, tc.maskedTarget) {
				t.Errorf("Expected masked target %q in %s config. Got:\n%s", tc.maskedTarget, tc.vendor, maskedText)
			}
		})
	}
}
