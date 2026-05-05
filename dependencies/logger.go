package dependencies

import (
	"log"
	"os"
	"sync/atomic"
)

var sessionCounter atomic.Uint64

var sessionColors = []string{
	"\033[36m", // cyan
	"\033[32m", // green
	"\033[33m", // yellow
	"\033[35m", // magenta
	"\033[34m", // blue
}

const colorReset = "\033[0m"

// colorEnabled is true only when stderr is an interactive terminal.
// When running under systemd, stderr is a pipe to journald — not a TTY —
// so we skip ANSI codes to avoid literal escape sequences in journal entries.
var colorEnabled = func() bool {
	info, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}()

type SessionLogger struct {
	color string
}

func NewSessionLogger() *SessionLogger {
	idx := sessionCounter.Add(1) - 1
	return &SessionLogger{color: sessionColors[idx%uint64(len(sessionColors))]}
}

func (l *SessionLogger) Printf(format string, args ...any) {
	if colorEnabled {
		log.Printf(l.color+format+colorReset, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (l *SessionLogger) Println(msg string) {
	if colorEnabled {
		log.Println(l.color + msg + colorReset)
	} else {
		log.Println(msg)
	}
}
