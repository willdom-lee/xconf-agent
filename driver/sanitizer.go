package driver

import (
	"embed"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed models/*.yaml
var modelsFS embed.FS

// DeviceModel represents the configuration structure for a network device vendor
type DeviceModel struct {
	PromptRegex   string   `yaml:"prompt_regex"`
	InitCommands  []string `yaml:"init_commands"`
	BackupCommand string   `yaml:"backup_command"`
	NoiseFilters  []string `yaml:"noise_filters"`
}

var (
	modelsCache = make(map[string]*DeviceModel)
	regexCache  = make(map[string][]*regexp.Regexp)
	cacheLock   sync.RWMutex
)

// GetDeviceModel retrieves and parses the embedded model configuration for a vendor
func GetDeviceModel(vendor string) (*DeviceModel, error) {
	vendor = strings.ToLower(vendor)
	cacheLock.RLock()
	model, exists := modelsCache[vendor]
	cacheLock.RUnlock()
	if exists {
		return model, nil
	}

	cacheLock.Lock()
	defer cacheLock.Unlock()

	// Double check
	if model, exists = modelsCache[vendor]; exists {
		return model, nil
	}

	// Read from embedded FS
	data, err := modelsFS.ReadFile("models/" + vendor + ".yaml")
	if err != nil {
		return nil, err
	}

	var m DeviceModel
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	modelsCache[vendor] = &m

	// Precompile regexes
	var regexes []*regexp.Regexp
	for _, pattern := range m.NoiseFilters {
		pat := pattern
		// Append optional trailing newline matching to avoid leaving behind blank lines
		if strings.HasSuffix(pat, "$") {
			pat = pat + `(?:\r?\n)?`
		} else if !strings.HasSuffix(pat, `(?:\r?\n)?`) && !strings.HasSuffix(pat, `\r?\n`) {
			pat = pat + `(?:\r?\n)?`
		}
		re, err := regexp.Compile(pat)
		if err == nil {
			regexes = append(regexes, re)
		}
	}
	regexCache[vendor] = regexes

	return &m, nil
}

// SanitizeConfig applies the vendor-specific RE2 filters to clean configurations
func SanitizeConfig(rawConfig []byte, vendor string) []byte {
	vendor = strings.ToLower(vendor)
	_, err := GetDeviceModel(vendor)
	if err != nil {
		// If model not found or fails, return raw config untouched (safe default)
		return rawConfig
	}

	cacheLock.RLock()
	regexes := regexCache[vendor]
	cacheLock.RUnlock()

	text := string(rawConfig)
	for _, re := range regexes {
		text = re.ReplaceAllString(text, "")
	}

	// Trim trailing/leading spaces & newlines
	return []byte(strings.TrimSpace(text))
}
