package crypto

import (
	"bufio"
	"bytes"
	"io"
	"regexp"
	"strings"
)

var maskRegexes = []*regexp.Regexp{
	// 1a. Plain password line: password (simple/cipher/7/5) <hash/plaintext>
	regexp.MustCompile(`(?i)(^\s*password\s+(?:(?:cipher|simple|\d+)\s+)?)(?:"[^"\r\n]+"|'[^'\r\n]+'|\S+)`),
	// 1b. Username password: username <user> [privilege <num>] password (simple/cipher/7/5) <hash/plaintext>
	regexp.MustCompile(`(?i)(\busername\s+\S+(?:\s+privilege\s+\d+)?\s+password\s+(?:(?:cipher|simple|\d+)\s+)?)(?:"[^"\r\n]+"|'[^'\r\n]+'|\S+)`),
	// 2a. Plain secret: secret (5) <hash>
	regexp.MustCompile(`(?i)(^\s*secret\s+(?:\d+\s+)?)(?:"[^"\r\n]+"|'[^'\r\n]+'|\S+)`),
	// 2b. Enable/Username secret: enable/username <user> [privilege <num>] secret (5) <hash>
	regexp.MustCompile(`(?i)(\b(?:enable|username\s+\S+(?:\s+privilege\s+\d+)?)\s+secret\s+(?:\d+\s+)?)(?:"[^"\r\n]+"|'[^'\r\n]+'|\S+)`),
	// 3. SNMP community: community (read|write) (cipher|simple) <community> (quoted or unquoted)
	regexp.MustCompile(`(?i)(community\s+(?:read|write)\s+(?:cipher|simple)?\s*)(?:"[^"\r\n]+"|'[^'\r\n]+'|\S+)`),
	// 4. Cisco/H3C key-string: key-string (cipher|simple) <key> (quoted or unquoted)
	regexp.MustCompile(`(?i)(key-string\s+(?:cipher|simple)?\s*)(?:"[^"\r\n]+"|'[^'\r\n]+'|\S+)`),
	// 5. General key hex: key hex <key> (quoted or unquoted)
	regexp.MustCompile(`(?i)(key\s+hex\s+)(?:"[^"\r\n]+"|'[^'\r\n]+'|\S+)`),
	// 6. Cisco enable password
	regexp.MustCompile(`(?i)(enable\s+password)\s+(.+)`),
	// 7. RADIUS server key
	regexp.MustCompile(`(?i)(radius-server\s+key)\s+(.+)`),
	// 8. TACACS server key
	regexp.MustCompile(`(?i)(tacacs-server\s+key)\s+(.+)`),
	// 9. NTP authentication key (MD5)
	regexp.MustCompile(`(?i)(ntp\s+authentication-key\s+\S+\s+md5)\s+(.+)`),
	// 10. Crypto ISAKMP key
	regexp.MustCompile(`(?i)(crypto\s+isakmp\s+key)\s+(.+?)\s+address`),
	// 11. IPsec pre-shared-key
	regexp.MustCompile(`(?i)(pre-shared-key)\s+(.+)`),
	// 12. WPA-PSK ASCII
	regexp.MustCompile(`(?i)(wpa-psk\s+ascii)\s+(.+)`),
}

// MaskingReader wraps an io.Reader and filters out credentials line-by-line on the fly.
type MaskingReader struct {
	reader *bufio.Reader
	buf    bytes.Buffer
	err    error
}

// NewMaskingReader creates a new io.Reader that masks sensitive lines on the fly.
func NewMaskingReader(r io.Reader) io.Reader {
	return &MaskingReader{
		reader: bufio.NewReader(r),
	}
}

// Read implements the io.Reader interface.
func (mr *MaskingReader) Read(p []byte) (int, error) {
	if mr.buf.Len() > 0 {
		return mr.buf.Read(p)
	}

	if mr.err != nil {
		return 0, mr.err
	}

	// Read next line using ReadString to preserve actual line endings
	line, err := mr.reader.ReadString('\n')
	if line != "" {
		hasLF := strings.HasSuffix(line, "\n")
		if hasLF {
			line = strings.TrimSuffix(line, "\n")
		}
		hasCR := strings.HasSuffix(line, "\r")
		if hasCR {
			line = strings.TrimSuffix(line, "\r")
		}

		maskedLine := MaskLine(line)

		if hasCR {
			maskedLine += "\r"
		}
		if hasLF {
			maskedLine += "\n"
		}

		mr.buf.WriteString(maskedLine)
	}

	if err != nil {
		mr.err = err
		if line == "" {
			return 0, err
		}
	}

	return mr.buf.Read(p)
}

// MaskLine applies regular expressions to replace configuration passwords with [MASKED].
func MaskLine(line string) string {
	for _, re := range maskRegexes {
		if re.MatchString(line) {
			line = re.ReplaceAllString(line, "${1}[MASKED]")
		}
	}
	return line
}

