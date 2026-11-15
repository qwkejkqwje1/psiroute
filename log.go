package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// logLine is one entry of the in-memory journal shown in the UI.
type logLine struct {
	Time  string `json:"time"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

// Logger keeps a bounded ring of recent lines for the UI and, in the core
// process, also writes them to psiroute.log (1.0.7): the journal survives a
// crash or a restart and can be sent in a report. The file is rotated to
// psiroute.log.1 at logFileMax, so at most two files are kept.
type Logger struct {
	mu       sync.Mutex
	lines    []logLine
	max      int
	minLevel int // 0=debug, 1=info, 2=warn, 3=error

	path string
	f    *os.File
	size int64
}

func parseLogLevel(lvl string) int {
	switch strings.ToLower(strings.TrimSpace(lvl)) {
	case "debug":
		return 0
	case "warn", "warning":
		return 2
	case "error", "err":
		return 3
	default:
		return 1 // info
	}
}

func (l *Logger) SetLevel(lvl string) {
	l.mu.Lock()
	l.minLevel = parseLogLevel(lvl)
	l.mu.Unlock()
}

const logFileMax = 1 << 20

var theLog = &Logger{max: 800}

func fileLine(day, clock, level, msg string) string {
	return day + " " + clock + " " + fmt.Sprintf("%-5s", level) + " " + msg + "\n"
}

func (l *Logger) add(level, msg string) {
	lvlNum := parseLogLevel(level)
	now := time.Now()
	clock := now.Format("15:04:05")
	l.mu.Lock()
	if lvlNum < l.minLevel {
		l.mu.Unlock()
		return
	}
	l.lines = append(l.lines, logLine{Time: clock, Level: level, Msg: msg})
	if len(l.lines) > l.max {
		l.lines = l.lines[len(l.lines)-l.max:]
	}
	l.writeLocked(fileLine(now.Format("2006-01-02"), clock, level, msg))
	l.mu.Unlock()
}

// raw writes multi-line text (a panic stack) to the file only.
func (l *Logger) raw(text string) {
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	l.mu.Lock()
	l.writeLocked(text)
	l.mu.Unlock()
}

func (l *Logger) writeLocked(s string) {
	if l.f == nil {
		return
	}
	if l.size > 0 && l.size+int64(len(s)) > logFileMax {
		l.rotateLocked()
		if l.f == nil {
			return
		}
	}
	n, _ := l.f.WriteString(s)
	l.size += int64(n)
}

func (l *Logger) rotateLocked() {
	_ = l.f.Close() // Windows cannot rename an open file
	l.f = nil
	_ = os.Remove(l.path + ".1")
	_ = os.Rename(l.path, l.path+".1")
	_ = l.openLocked()
}

func (l *Logger) openLocked() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	l.f, l.size = f, 0
	if st, err := f.Stat(); err == nil {
		l.size = st.Size()
	}
	return nil
}

// openFile starts writing the journal to path. Lines logged before (they are
// in memory) are written first, so the start of the run is in the file too.
func (l *Logger) openFile(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		_ = l.f.Close()
		l.f = nil
	}
	l.path = path
	if err := l.openLocked(); err != nil {
		return err
	}
	now := time.Now()
	l.writeLocked(fmt.Sprintf("\n---- %s Psiroute %s, pid %d\n", now.Format("2006-01-02 15:04:05"), version, os.Getpid()))
	day := now.Format("2006-01-02")
	for _, ln := range l.lines {
		l.writeLocked(fileLine(day, ln.Time, ln.Level, ln.Msg))
	}
	return nil
}

func (l *Logger) closeFile() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		_ = l.f.Close()
		l.f = nil
	}
}

// filePath is the journal file, "" when this process does not write one.
func (l *Logger) filePath() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return ""
	}
	return l.path
}

func (l *Logger) snapshot() []logLine {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]logLine, len(l.lines))
	copy(out, l.lines)
	return out
}

// logf is the package-wide logging entry point, matching ProxyDesk's helper.
func logf(level, format string, a ...any) {
	theLog.add(level, fmt.Sprintf(format, a...))
}
