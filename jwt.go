package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/robfig/cron/v3"
)

type cronJob struct {
	EntryID  cron.EntryID
	Schedule string
}

// Helper to extract JWT issuer for auto-detecting Supabase URL
func extractIssuerFromJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("JWT token must consist of 3 parts separated by dots")
	}

	payloadSegment := parts[1]
	decoded, err := base64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		return "", fmt.Errorf("failed to decode token claims payload: %w", err)
	}

	var claims struct {
		Iss string `json:"iss"`
	}

	if err := json.Unmarshal(decoded, &claims); err != nil {
		return "", fmt.Errorf("failed to parse token JSON payload: %w", err)
	}

	return claims.Iss, nil
}


// Generate RFC4122 v4 UUID
func generateUUID() string {
	uuid := make([]byte, 16)
	if _, err := rand.Read(uuid); err != nil {
		panic(fmt.Sprintf("crypto/rand.Read failed: %v", err))
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}
