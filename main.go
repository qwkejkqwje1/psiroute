package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

const version = "2.4.0"

// crashRestarts: how many times the watchdog restarted the core after a crash.
var crashRestarts int

// ensurePortableDirs создаёт подпапки reports, tmp и lists внутри рабочей папки
// и перенаправляет переменные окружения TMP/TEMP/GOTMPDIR внутрь dataDir/tmp,
// чтобы ни psiphon-tunnel-core, ни wintun, ни Go runtime не писали на диск C:.
func ensurePortableDirs(dir string) {
	if dir == "" {
		return
	}
	tmpDir := filepath.Join(dir, "tmp")
	repDir := filepath.Join(dir, "reports")
	lstDir := filepath.Join(dir, "lists")
	_ = os.MkdirAll(tmpDir, 0o700)
	_ = os.MkdirAll(repDir, 0o700)
	_ = os.MkdirAll(lstDir, 0o700)
	_ = os.Setenv("TMP", tmpDir)
	_ = os.Setenv("TEMP", tmpDir)
	_ = os.Setenv("TMPDIR", tmpDir)
	if os.Getenv("GOTMPDIR") == "" {
		_ = os.Setenv("GOTMPDIR", tmpDir)
	}
}

// dataDirFor возвращает папку хранения данных строго в Portable-режиме
// рядом с исполняемым файлом (или на диске D:), без откатов в os.UserConfigDir() на диске C:.
func dataDirFor() string {
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		// Если psiroute.json уже лежит непосредственно рядом с psiroute.exe — храним всё рядом с exe
		if _, err := os.Stat(filepath.Join(exeDir, "psiroute.json")); err == nil {
			ensurePortableDirs(exeDir)
			return exeDir
		}
		if f, err := os.CreateTemp(exeDir, ".psiroute-w"); err == nil {
			f.Close()
			os.Remove(f.Name())
			ensurePortableDirs(exeDir)
			return exeDir
		}
		subData := filepath.Join(exeDir, "data")
		if err := os.MkdirAll(subData, 0o700); err == nil {
			ensurePortableDirs(subData)
			return subData
		}
	}
	if st, err := os.Stat(`D:\`); err == nil && st.IsDir() {
		d := filepath.Join(`D:\PsiRoute`, "data")
		_ = os.MkdirAll(d, 0o700)
		ensurePortableDirs(d)
		return d
	}
	d, err := filepath.Abs("data")
	if err != nil {
		d = "."
	}
	_ = os.MkdirAll(d, 0o700)
	ensurePortableDirs(d)
	return d
}

func main() {
	cfgFlag := flag.String("config", "", "путь к конфигурационному файлу psiroute.json (ENV: PSIROUTE_CONFIG)")
	profileFlag := flag.String("profile", "", "выбор активного профиля при запуске (ENV: PSIROUTE_PROFILE)")
	modeFlag := flag.String("mode", "", "режим работы: tun | proxy | psiphon | rules | auto (ENV: PSIROUTE_MODE)")
	listenFlag := flag.String("listen", "", "адрес и порт локального SOCKS5/HTTP прокси, напр. 127.0.0.1:1080 (ENV: PSIROUTE_LISTEN)")
	headlessFlag := flag.Bool("headless", false, "консольный режим без окна Gio и системного трея (ENV: PSIROUTE_HEADLESS)")
	noGUI := flag.Bool("no-gui", false, "синоним --headless: запуск без окна и трея")
	trayFlag := flag.Bool("tray", false, "запуск свернутым в системный трей (ENV: PSIROUTE_MINIMIZED)")
	minimized := flag.Bool("minimized", false, "синоним --tray: запуск свернутым в системный трей")
	autoconnectFlag := flag.Bool("autoconnect", false, "автоматический запуск туннеля при старте (ENV: PSIROUTE_AUTOCONNECT)")
	webAddrFlag := flag.String("web-addr", "", "адрес встроенного веб-интерфейса, напр. 127.0.0.1:9090 (ENV: PSIROUTE_WEB_ADDR)")
	noWebFlag := flag.Bool("no-web", false, "отключить встроенный веб-интерфейс в консольном режиме (ENV: PSIROUTE_NO_WEB)")
	logLevelFlag := flag.String("log-level", "", "уровень логирования: debug | info | warn | error (ENV: PSIROUTE_LOG_LEVEL)")
	logFileFlag := flag.String("log-file", "", "путь к файлу журнала (ENV: PSIROUTE_LOG_FILE)")
	memLimitFlag := flag.Int("mem-limit", 0, "мягкий лимит памяти ОЗУ в МБ (GOMEMLIMIT, напр. 96) (ENV: PSIROUTE_MEM_LIMIT)")
	testConfigFlag := flag.Bool("test-config", false, "проверить конфигурационный файл и правила и завершиться (exit 0 / exit 1)")
	window := flag.String("window", "", "internal: window process for this UI address")
	parent := flag.Int("parent", 0, "internal")
	probe := flag.Bool("probe", false, "internal: DPI probe worker")
	probeDir := flag.String("probe-dir", "", "internal")
	probeRegion := flag.String("probe-region", "", "internal")
	psiWorker := flag.Bool("psi-worker", false, "internal: Psiphon worker for one exit country")
	workerDir := flag.String("worker-dir", "", "internal")
	workerRegion := flag.String("worker-region", "", "internal")
	pprofAddr := flag.String("pprof", "", "test: pprof address, e.g. 127.0.0.1:6060")
	showVer := flag.Bool("version", false, "вывести версию сборки")
	selftest := flag.Bool("selftest", false, "самопроверка: отчёт в psiroute-selftest.txt")
	noWatch := flag.Bool("no-watchdog", false, "без сторожа (не перезапускать после сбоя)")
	core := flag.Bool("core", false, "internal: started by the watchdog")
	restarts := flag.Int("restarts", 0, "internal")
	waitPID := flag.Int("wait-pid", 0, "internal: дождаться выхода прежней копии (перезапуск от администратора)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "PsiRoute %s — гибридный клиент обхода блокировок (Psiphon, WARP, Анти-DPI, TUN)\n\n", version)
		fmt.Fprintf(os.Stderr, "Использование:\n  psiroute [флаги]\n\nОсновные флаги:\n")
		fmt.Fprintf(os.Stderr, "  --config <path>        Путь к конфигурационному файлу (по умолчанию psiroute.json)\n")
		fmt.Fprintf(os.Stderr, "  --profile <name>       Выбор активного профиля при запуске (ru-everyday, games-calls, full-vpn...)\n")
		fmt.Fprintf(os.Stderr, "  --mode <tun|proxy>     Переопределение режима перехвата (tun, proxy, rules, psiphon, auto)\n")
		fmt.Fprintf(os.Stderr, "  --listen <ip:port>     Адрес и порт локального SOCKS5/HTTP прокси (напр. 127.0.0.1:1080)\n")
		fmt.Fprintf(os.Stderr, "  --headless, --no-gui   Фоновый консольный режим без окна Gio и системного трея\n")
		fmt.Fprintf(os.Stderr, "  --tray, --minimized    Запуск свернутым в системный трей\n")
		fmt.Fprintf(os.Stderr, "  --autoconnect          Автоматический запуск туннеля сразу при старте\n")
		fmt.Fprintf(os.Stderr, "  --web-addr <ip:port>   Адрес встроенного веб-интерфейса (напр. 127.0.0.1:9090)\n")
		fmt.Fprintf(os.Stderr, "  --no-web               Отключить встроенный веб-интерфейс\n")
		fmt.Fprintf(os.Stderr, "  --log-level <level>    Уровень логирования: debug | info | warn | error\n")
		fmt.Fprintf(os.Stderr, "  --log-file <path>      Путь к файлу журнала\n")
		fmt.Fprintf(os.Stderr, "  --mem-limit <MB>       Мягкий лимит памяти ОЗУ в МБ (GOMEMLIMIT, напр. 96)\n")
		fmt.Fprintf(os.Stderr, "  --test-config          Валидация конфига и правил с выводом ошибок (exit 0 / exit 1)\n")
		fmt.Fprintf(os.Stderr, "  --selftest             Запуск встроенной самопроверки\n")
		fmt.Fprintf(os.Stderr, "  --version              Вывод версии сборки\n\n")
		fmt.Fprintf(os.Stderr, "Приоритет настроек: CLI-флаги > Переменные окружения (PSIROUTE_*) > config.json > По умолчанию.\n")
	}
	flag.Parse()

	if *headlessFlag || os.Getenv("PSIROUTE_HEADLESS") == "1" || strings.EqualFold(os.Getenv("PSIROUTE_HEADLESS"), "true") {
		*noGUI = true
	}
	if *trayFlag || os.Getenv("PSIROUTE_MINIMIZED") == "1" || strings.EqualFold(os.Getenv("PSIROUTE_MINIMIZED"), "true") {
		*minimized = true
	}
	if *cfgFlag == "" {
		if envCfg := strings.TrimSpace(os.Getenv("PSIROUTE_CONFIG")); envCfg != "" {
			*cfgFlag = envCfg
		}
	}
	activeCLIOverrides = cliOverrides{
		Profile:     strings.TrimSpace(*profileFlag),
		Mode:        strings.TrimSpace(*modeFlag),
		Listen:      strings.TrimSpace(*listenFlag),
		WebAddr:     strings.TrimSpace(*webAddrFlag),
		NoWeb:       *noWebFlag,
		Autoconnect: *autoconnectFlag,
		LogLevel:    strings.TrimSpace(*logLevelFlag),
		LogFile:     strings.TrimSpace(*logFileFlag),
		MemLimitMB:  *memLimitFlag,
	}
	if *waitPID > 0 {
		waitForPID(*waitPID)
	}

	if *showVer {
		fmt.Println("psiroute", version)
		return
	}
	setupMemory() // every process: core, window, country workers, probe
	if activeCLIOverrides.MemLimitMB > 0 {
		SetCustomMemoryLimitMB(activeCLIOverrides.MemLimitMB)
	}
	if *psiWorker {
		runPsiWorker(*cfgFlag, *workerDir, *workerRegion)
		return
	}
	if *probe {
		runProbe(*probeDir, *probeRegion)
		return
	}
	dir := dataDirFor()
	setupCrashOutput(dir)
	path := *cfgFlag
	if path == "" {
		path = filepath.Join(dir, "psiroute.json")
	}
	// Баг №3: --test-config выполняется ДО запуска watchdog, со строгой проверкой синтаксиса JSON.
	if *testConfigFlag {
		cfg, loadErr := loadConfigStrict(path)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "Конфигурация %s содержит ошибку синтаксиса: %v\n", path, loadErr)
			os.Exit(1)
		}
		cfg.applyCLIOverrides(activeCLIOverrides)
		errs := ValidateConfig(cfg)
		if len(errs) > 0 {
			fmt.Fprintf(os.Stderr, "Конфигурация %s содержит ошибки (%d):\n", path, len(errs))
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "  - %s\n", e)
			}
			os.Exit(1)
		}
		fmt.Printf("Конфигурация %s корректна: режим=%s, прокси=%s, правил=%d\n", path, cfg.Routing.Mode, cfg.General.Listen, len(cfg.Routing.Rules))
		os.Exit(0)
	}
	if *window != "" {
		runWindowProcess(dir, *window, *parent)
		return
	}
	if *selftest {
		os.Exit(runSelftestCLI(dir))
	}
	// The watchdog: a tiny parent that restarts the core after a crash (Go
	// panics outside a recover, fatal runtime errors). --no-gui runs are
	// usually supervised by something else and stay single-process.
	if !*core && !*noWatch && !*noGUI && *pprofAddr == "" {
		if code, ran := runWatchdog(dir); ran {
			os.Exit(code)
		}
	}
	if *core {
		watchdogPID = os.Getppid()
		crashRestarts = *restarts
	}
	crash := findCrash(dir)
	setupCrashOutput(dir)
	if *pprofAddr != "" {
		pl, pw := pprofLoopbackAddr(*pprofAddr)
		if pw != "" {
			logf("error", "%s", pw)
		}
		safeGo("main", func() { _ = http.ListenAndServe(pl, nil) }) // profiling for tests only; loopback only (A-17/11)
	}
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(sigCtx)
	defer cancel()

	a := NewApp(ctx, cancel, path, dir)
	logPath := filepath.Join(dir, "psiroute.log")
	if a.cfg.General.LogFile != "" {
		logPath = a.cfg.General.LogFile
	}
	theLog.SetLevel(a.cfg.General.LogLevel)
	if err := theLog.openFile(logPath); err != nil {
		logf("warn", "Журнал не записывается в файл: %v", err)
	}
	defer theLog.closeFile()
	if err := a.Start(); err != nil {
		if errors.Is(err, errAlreadyRunning) {
			theLog.closeFile()
			// Second launch: show the window of the running instance.
			if !*noGUI {
				runWindowProcess(dir, a.uiURL(), 0)
			}
			return
		}
		logf("error", "Psiroute не запустился: %v", err)
		fmt.Fprintln(os.Stderr, "psiroute:", err)
		if !*noGUI {
			showFatal("Psiroute не запустился:\n\n" + err.Error()) // -H windowsgui has no console
		}
		os.Exit(1)
	}
	if crash.unseen {
		logf("warn", "Прошлый запуск завершился сбоем (%s): %s — подробности в crash.log", crash.At.Format("02.01 15:04"), crash.Headline)
		crash.markSeen(dir)
	}
	if crashRestarts > 0 {
		logf("warn", "Psiroute перезапущен после сбоя (%d-й раз подряд)", crashRestarts)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) && a.cfg.corruptError() == "" {
		_ = a.cfg.saveOrReport("main") // first run: write defaults only if file did not exist and was not corrupt
	}
	if *noGUI {
		fmt.Println("Psiroute запущен, интерфейс:", a.uiURL())
		<-ctx.Done()
	} else {
		// Tray icon in this process; the window is a separate process that
		// takes its WebView2 memory with it when closed.
		runDesktop(ctx, a, dir, !*minimized)
	}
	a.Shutdown()
}
