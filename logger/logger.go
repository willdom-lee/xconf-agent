package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Level string

const (
	LevelInfo    Level = "INFO"
	LevelSuccess Level = "SUCCESS"
	LevelWarn    Level = "WARN"
	LevelError   Level = "ERROR"
	LevelFatal   Level = "FATAL"
)

var dataDir string

// SetDataDir sets the base directory for dynamic files like logs and history.
func SetDataDir(configDir string) {
	dataDir = configDir
}

// Log prints a structured log to stdout and appends it to data/agent.log.
func Log(level Level, component string, deviceCtx string, format string, v ...interface{}) {
	timestamp := time.Now().Format(time.RFC3339)
	msg := fmt.Sprintf(format, v...)
	var logLine string
	if deviceCtx != "" {
		// Truncate full UUIDs to 8 characters to keep logs compact and readable
		cleanCtx := deviceCtx
		if len(deviceCtx) == 36 {
			cleanCtx = deviceCtx[:8]
		}
		logLine = fmt.Sprintf("%s [%s] [%s] [dev:%s] %s\n", timestamp, level, component, cleanCtx, msg)
	} else {
		logLine = fmt.Sprintf("%s [%s] [%s] %s\n", timestamp, level, component, msg)
	}

	// 1. Output to stdout
	fmt.Print(logLine)

	// 2. Append to data/agent.log
	logDir := filepath.Join(dataDir, "data")
	if err := os.MkdirAll(logDir, 0755); err == nil {
		logFilePath := filepath.Join(logDir, "agent.log")
		f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			_, _ = f.WriteString(logLine)
		}
	}
}

func Info(component, deviceCtx, format string, v ...interface{}) {
	Log(LevelInfo, component, deviceCtx, format, v...)
}

func Success(component, deviceCtx, format string, v ...interface{}) {
	Log(LevelSuccess, component, deviceCtx, format, v...)
}

func Warn(component, deviceCtx, format string, v ...interface{}) {
	Log(LevelWarn, component, deviceCtx, format, v...)
}

func Error(component, deviceCtx, format string, v ...interface{}) {
	Log(LevelError, component, deviceCtx, format, v...)
}

func Fatal(component, deviceCtx, format string, v ...interface{}) {
	Log(LevelFatal, component, deviceCtx, format, v...)
}
