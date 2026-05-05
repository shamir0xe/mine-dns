package dependencies

import (
	"log"
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

type SessionLogger struct {
	color string
}

func NewSessionLogger() *SessionLogger {
	idx := sessionCounter.Add(1) - 1
	return &SessionLogger{color: sessionColors[idx%uint64(len(sessionColors))]}
}

func (l *SessionLogger) Printf(format string, args ...any) {
	log.Printf(l.color+format+colorReset, args...)
}

func (l *SessionLogger) Println(msg string) {
	log.Println(l.color + msg + colorReset)
}
