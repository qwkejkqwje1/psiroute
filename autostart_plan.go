package main

import (
	"sync"
	"sync/atomic"
)

// Autostart policy (audit A-05). It lives outside platform_windows.go so it can
// be tested without Windows.
//
// A scheduled task with the highest privileges runs os.Executable() as
// administrator at every logon. If ordinary users can write to the folder of
// that exe, any of them could replace the program and get administrator rights.
// So the privileged task is registered only when the location is protected, and
// only one mechanism (task OR the HKCU Run value) is ever active.

// Windows access-mask bits that let a holder change a file or a folder.
const (
	aclFileWriteData   = 0x00000002 // FILE_WRITE_DATA / FILE_ADD_FILE
	aclFileAppendData  = 0x00000004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
	aclFileDeleteChild = 0x00000040
	aclDelete          = 0x00010000
	aclWriteDAC        = 0x00040000
	aclWriteOwner      = 0x00080000
	aclGenericAll      = 0x10000000
	aclGenericWrite    = 0x40000000
)

// aceMaskAllowsWrite reports whether an access mask granted to ordinary users
// allows changing files in the location.
func aceMaskAllowsWrite(mask uint32) bool {
	const w = aclFileWriteData | aclFileAppendData | aclFileDeleteChild | aclDelete |
		aclWriteDAC | aclWriteOwner | aclGenericAll | aclGenericWrite
	return mask&w != 0
}

// autostartPlan says what setAutostart(true) must do.
type autostartPlan struct {
	UseTask      bool // register the scheduled task (RL HIGHEST)
	UseRunKey    bool // write the HKCU Run value
	RemoveTask   bool
	RemoveRunKey bool
	Warning      string // shown in the log and in the API answer; empty = nothing to warn about
}

const (
	autostartWarnWritable = "Папка с программой доступна для записи обычным пользователям, поэтому автозапуск с правами администратора не включён: иначе любой пользователь мог бы подменить программу. Используется обычный автозапуск без повышенных прав. Для TUN и фильтров переместите Psiroute в защищённую папку (например, Program Files) и включите автозапуск снова"
	autostartWarnUnknown  = "Не удалось проверить, кто может писать в папку с программой, поэтому автозапуск с правами администратора не включён. Используется обычный автозапуск без повышенных прав"
)

// planAutostart chooses ONE mechanism.
//   - elevated, protected folder        -> task, no Run value
//   - elevated, writable/unknown folder -> Run value only, an old privileged task is removed, warning
//   - not elevated, a task already there -> keep the task (cannot be replaced), no Run value
//   - not elevated, no task              -> Run value
func planAutostart(elevated, dirUserWritable bool, dirCheckErr error, taskExists bool) autostartPlan {
	if elevated {
		switch {
		case dirCheckErr != nil:
			return autostartPlan{UseRunKey: true, RemoveTask: true, Warning: autostartWarnUnknown}
		case dirUserWritable:
			return autostartPlan{UseRunKey: true, RemoveTask: true, Warning: autostartWarnWritable}
		default:
			return autostartPlan{UseTask: true, RemoveRunKey: true}
		}
	}
	if taskExists {
		return autostartPlan{RemoveRunKey: true}
	}
	return autostartPlan{UseRunKey: true}
}

var (
	autostartWarnMu  sync.Mutex
	autostartWarnTxt string
)

func setAutostartWarning(s string) {
	autostartWarnMu.Lock()
	autostartWarnTxt = s
	autostartWarnMu.Unlock()
}

// autostartWarning is the last warning of setAutostart ("" when none).
func autostartWarning() string {
	autostartWarnMu.Lock()
	defer autostartWarnMu.Unlock()
	return autostartWarnTxt
}

// autostartCache keeps the last known autostart state: autostartEnabled() starts
// schtasks.exe, which is too slow to run on every status poll of the UI.
// 0 = not read yet, 1 = off, 2 = on.
var autostartCache atomic.Int32

// refreshAutostartCache reads the real state once and remembers it.
func refreshAutostartCache() bool {
	on := autostartEnabled()
	if on {
		autostartCache.Store(2)
	} else {
		autostartCache.Store(1)
	}
	return on
}

// autostartCached is the remembered autostart state for the status API.
func autostartCached() bool { return autostartCache.Load() == 2 }
