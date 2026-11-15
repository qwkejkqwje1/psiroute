package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

// The probe tries several DPI / protocol combinations one by one and reports
// which connects fastest. Because tunnel-core's datastore is process-global and
// cannot be opened twice, the probe runs in a separate process launched with
// --probe; it streams one JSON line per combination to stdout. The GUI parses
// those lines and shows a ranking.

const psiProbeTimeout = 40 * time.Second

type probeStrategy struct {
	ID     string
	Name   string
	DPI    string
	Protos string
}

// psiDPIStrategies is the ordered probe matrix.
func psiDPIStrategies() []probeStrategy {
	return []probeStrategy{
		{ID: "std", Name: "стандартный обход", DPI: ""},
		{ID: "off", Name: "без обхода", DPI: "off"},
		{ID: "hello", Name: "разрез TLS", DPI: "hello"},
		{ID: "light", Name: "лёгкое дробление", DPI: "light"},
		{ID: "strong", Name: "сильное дробление", DPI: "strong"},
		{ID: "meek", Name: "CDN (meek)", Protos: "meek"},
		{ID: "tls", Name: "TLS", Protos: "tls"},
		{ID: "quic", Name: "QUIC", DPI: "off", Protos: "quic"},
		{ID: "ossh", Name: "OSSH", Protos: "ossh"},
	}
}

type probeResult struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	DPI       string `json:"dpi"`
	Protos    string `json:"protos"`
	OK        bool   `json:"ok"`
	ConnectMs int    `json:"connect_ms"`
	RttMs     int    `json:"rtt_ms"`
	Kbps      int    `json:"kbps"`
	Proto     string `json:"proto"`
	Region    string `json:"region"`
	IP        string `json:"ip"`
	Note      string `json:"note"`
}

// runProbe is the entry point for the --probe subprocess.
func runProbe(dir, region string) {
	ensurePortableDirs(dir)
	enc := json.NewEncoder(os.Stdout)
	deadline := time.Now().Add(8 * time.Minute)
	zeroTries := 0
	for _, s := range psiDPIStrategies() {
		if time.Now().After(deadline) {
			break
		}
		res := probeOne(dir, region, s)
		if res.ConnectMs == 0 && !res.OK {
			zeroTries++
		}
		_ = enc.Encode(res)
		if zeroTries >= 3 {
			_ = enc.Encode(probeResult{ID: "_error", Note: "не удалось получить список серверов — проверьте доступ в интернет"})
			return
		}
	}
}

func probeOne(dir, region string, s probeStrategy) probeResult {
	r := probeResult{ID: s.ID, Name: s.Name, DPI: s.DPI, Protos: s.Protos}
	dataDir := filepath.Join(dir, "probe-"+s.ID)
	_ = os.MkdirAll(dataDir, 0o700)
	cfg := &psiphon.Config{
		EgressRegion:                       region,
		DisableLocalSocksProxy:             true,
		DisableLocalHTTPProxy:              true,
		PropagationChannelId:               psiPropagationChannelID,
		SponsorId:                          psiSponsorID,
		RemoteServerListDownloadFilename:   "remote_server_list",
		RemoteServerListSignaturePublicKey: psiRSLKey,
		RemoteServerListURLs:               psiRSLURLs(),
		EmitDiagnosticNotices:              false,
		NetworkID:                          fmt.Sprintf("probe-%d", time.Now().UnixNano()),
		ClientPlatform:                     psiPlatform,
		DataRootDirectory:                  dataDir,
		TunnelPoolSize:                     1,
		EstablishTunnelTimeoutSeconds:      ptr(int(psiProbeTimeout.Seconds())),
	}
	if s.DPI != "" || s.Protos == "" {
		applyDPI(cfg, s.DPI)
	}
	if set := psiProtoSets[s.Protos]; len(set) > 0 {
		cfg.LimitTunnelProtocols = append([]string(nil), set...)
	}
	if err := cfg.Commit(true); err != nil {
		r.Note = short(err.Error(), 120)
		return r
	}
	if err := psiphon.OpenDataStore(cfg); err != nil {
		r.Note = short(err.Error(), 120)
		return r
	}
	defer psiphon.CloseDataStore()

	connected := make(chan *psiphon.Controller, 1)
	var proto string
	psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(func(b []byte) {
		var n psiNotice
		if json.Unmarshal(b, &n) == nil && n.Type == "ActiveTunnel" {
			if pr, _ := n.Data["protocol"].(string); pr != "" {
				proto = pr
			}
		}
	}))
	ctl, err := psiphon.NewController(cfg)
	if err != nil {
		r.Note = short(err.Error(), 120)
		return r
	}
	ctx, cancel := context.WithTimeout(context.Background(), psiProbeTimeout+5*time.Second)
	defer cancel()
	runDone := make(chan struct{})
	go func() { ctl.Run(ctx); close(runDone) }()
	defer func() { cancel(); <-runDone }()

	t0 := time.Now()
	go func() {
		for ctx.Err() == nil {
			if c, derr := ctl.Dial("www.gstatic.com:80", nil); derr == nil {
				c.Close()
				select {
				case connected <- ctl:
				default:
				}
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()

	select {
	case <-time.After(psiProbeTimeout):
		r.Note = "тайм-аут"
		return r
	case <-connected:
	}
	r.OK = true
	r.ConnectMs = int(time.Since(t0).Milliseconds())
	r.Proto = proto

	pdial := func(c context.Context, network, addr string) (net.Conn, error) {
		return ctl.Dial(addr, nil)
	}
	rt := &http.Transport{DialContext: pdial}
	tctx, tcancel := context.WithTimeout(context.Background(), 20*time.Second)
	if tr, e := getTrace(tctx, pdial); e == nil {
		r.IP, r.Region = tr.IP, tr.Loc
	}
	tcancel()

	t1 := time.Now()
	cl := &http.Client{Transport: rt}
	if req, e := http.NewRequest("GET", speedURL, nil); e == nil {
		if resp, e2 := cl.Do(req); e2 == nil {
			buf := make([]byte, 64<<10)
			var total int64
			for time.Since(t1) < 8*time.Second {
				n, e3 := resp.Body.Read(buf)
				total += int64(n)
				if e3 != nil {
					break
				}
			}
			resp.Body.Close()
			secs := time.Since(t1).Seconds()
			if total >= 32<<10 && secs > 0 {
				r.Kbps = int(float64(total) / 1024 / secs)
			}
		}
	}
	r.RttMs = r.ConnectMs
	cl.CloseIdleConnections()
	return r
}
