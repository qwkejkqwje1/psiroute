# Psiphon Tunnel-Core Config & Notice Inventory

- **Pinned module (`go.mod`)**: `github.com/Psiphon-Labs/psiphon-tunnel-core v0.0.14-beta-ios.0.20261030175543-aabc0b3a6397`
- **Rule 2 compliance**: Fields and notices are strictly separated into:
  1. **VERIFIED IN PINNED CODEBASE** — already compiled against `aabc0b3a6397` in PsiRoute (`psi.go`, `probe.go`, `country.go`).
  2. **NOT VERIFIED AGAINST EXACT COMMIT `aabc0b3a6397`** — observed in upstream [`github.com/Psiphon-Labs/psiphon-tunnel-core` `master` (`d6ac859`)](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/master/psiphon/config.go) and [`pkg.go.dev`](https://pkg.go.dev/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon), but **not yet checked against the local Go module cache** for `aabc0b3a6397` because the source archive does not contain `vendor/`. Do not use Tier B fields in production code until verified locally with `go doc` (commands below).

---

## 1. `psiphon.Config` Fields

### 1.1 VERIFIED IN PINNED CODEBASE (`psi.go`, `probe.go`)

| Field | Type (observed in codebase) | Current PsiRoute Usage |
|---|---|---|
| `DataRootDirectory` | `string` | `psi.go:745`, `probe.go:99` |
| `PropagationChannelId` | `string` | `psi.go:737`, `probe.go:91` (currently `FFFFFFFFFFFFFFFF`) |
| `SponsorId` | `string` | `psi.go:738`, `probe.go:92` (currently `FFFFFFFFFFFFFFFF`) |
| `ClientPlatform` | `string` | `psi.go:744`, `probe.go:98` |
| `EgressRegion` | `string` | `psi.go:734`, `probe.go:88` |
| `DisableLocalSocksProxy` | `bool` | `psi.go:735`, `probe.go:89` |
| `DisableLocalHTTPProxy` | `bool` | `psi.go:736`, `probe.go:90` |
| `RemoteServerListDownloadFilename` | `string` (deprecated upstream; see `MigrateRemoteServerListDownloadFilename`) | `psi.go:739`, `probe.go:93` |
| `RemoteServerListSignaturePublicKey` | `string` | `psi.go:740`, `probe.go:94` |
| `RemoteServerListURLs` | `parameters.TransferURLs` | `psi.go:741`, `probe.go:95` |
| `EmitDiagnosticNotices` | `bool` | `psi.go:742`, `probe.go:96` |
| `NetworkID` | `string` | `psi.go:743`, `probe.go:97` |
| `TunnelPoolSize` | `int` | `psi.go:746`, `probe.go:100` |
| `EstablishTunnelPausePeriodSeconds` | `*int` | `psi.go:747` |
| `EstablishTunnelTimeoutSeconds` | `*int` | `psi.go:750`, `probe.go:101` |
| `UpstreamProxyURL` | `string` | `psi.go:760`, `psi.go:762`, `psi.go:765` |
| `UpstreamProxyAllowAllServerEntrySources` | `*bool` | `psi.go:774` |
| `LimitTunnelProtocols` | `[]string` | `psi.go:769`, `psi.go:771`, `probe.go:107` |
| `FragmentorProbability` | `*float64` | `psi.go:790`, `psi.go:800`, `psi.go:804` |
| `FragmentorMinTotalBytes` | `*int` | `psi.go:791` |
| `FragmentorMaxTotalBytes` | `*int` | `psi.go:792` |
| `FragmentorMinWriteBytes` | `*int` | `psi.go:793` |
| `FragmentorMaxWriteBytes` | `*int` | `psi.go:794` |
| `FragmentorMinDelayMicroseconds` | `*int` | `psi.go:795` |
| `FragmentorMaxDelayMicroseconds` | `*int` | `psi.go:796` |
| `TLSFragmentClientHelloProbability` | `*float64` | `psi.go:801`, `psi.go:812` |

### 1.2 Candidate Tuning / Seed / DNS / Tactics Fields

> **A-01: подтверждено компиляцией против закреплённого коммита `aabc0b3a6397`** (сборка Rocky, Windows, Go 1.26.2).
> Поля, которые реально выставляет `psi_tuning.go`, существуют в закреплённом коммите: `NetworkLatencyMultiplier`,
> `ConnectionWorkerPoolSize`, `StaggerConnectionWorkersMilliseconds`, `LimitIntensiveConnectionWorkers`,
> `EstablishTunnelTimeoutSeconds`, `DNSResolverAlternateServers`, `DNSResolverPreferAlternateServerProbability`.
> Их не удаляем и не прячем за рефлексию. Остальные строки таблицы ниже по-прежнему НЕ проверены сборкой.

Observed in upstream [`psiphon/config.go` (`master`)](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/master/psiphon/config.go). Verify locally before using in Steps 2–5:

| Group | Field Name | Upstream Type | Intended Use (Steps 2–5) |
|---|---|---|---|
| Latency & timeouts | `NetworkLatencyMultiplier` | `float64` (`>= 1.0`) | Step 4: scale timeouts on slow/throttled carriers |
| Latency & timeouts | `TunnelConnectTimeoutSeconds` | `*int` | Step 4: per-tunnel dial timeout |
| Latency & timeouts | `EstablishTunnelServerAffinityGracePeriodMilliseconds` | `*int` | Step 3–4: affinity server head start |
| Worker pool | `ConnectionWorkerPoolSize` | `int` | Step 4: wider initial racing pool |
| Worker pool | `ConnectionWorkerPoolMaxSize` | `int` | Step 4: cap worker pool under tactics |
| Worker pool | `StaggerConnectionWorkersMilliseconds` | `int` | Step 4: stagger worker launches |
| Worker pool | `LimitIntensiveConnectionWorkers` | `int` | Step 4: cap resource-heavy protocols |
| Protocol phasing | `InitialLimitTunnelProtocols` | `[]string` | Step 3–4: prioritize fast/resistant protocols first |
| Protocol phasing | `InitialLimitTunnelProtocolsCandidateCount` | `int` | Step 3–4: candidate count for initial phase |
| Seed / OSL | `ObfuscatedServerListRootURLs` | `parameters.TransferURLs` | Step 2: OSL root URLs (if official values provided) |
| Seed / OSL | `DisableRemoteServerListFetcher` | `bool` | Step 2: disable built-in RSL fetch when testing/offline |
| Seed / OSL | `FetchRemoteServerListRetryPeriodMilliseconds` | `*int` | Step 2: retry cadence for RSL fetch |
| Seed / OSL | `ServerEntrySignaturePublicKey` | `string` | Step 2: verify individual signed server entries (if key available) |
| DNS | `DNSServerGetter` | `DNSServerGetter` | Step 4: supply custom DNS server list to tunnel-core |
| DNS | `DNSResolverAlternateServers` | `[]string` | Step 4: alternate DNS servers (testing-marked upstream) |
| DNS | `DNSResolverPreferredAlternateServers` | `[]string` | Step 4: preferred alternate DNS servers (testing-marked upstream) |
| DNS | `DNSResolverPreferAlternateServerProbability` | `*float64` | Step 4: prefer alternate DNS over system resolver |
| DNS | `DNSResolverRequestTimeoutMilliseconds` | `*int` | Step 4: DNS request timeout |
| DNS | `DNSResolverAwaitTimeoutMilliseconds` | `*int` | Step 4: DNS await timeout |
| Tactics & identity | `ClientVersion` | `string` | Step 5: reported app version |
| Tactics & identity | `DeviceRegion` | `string` | Step 5: ISO 3166-1 alpha-2 region hint |
| Tactics & identity | `SessionID` | `string` (32 lowercase hex) | Step 3: preserve session across controllers if needed |
| Tactics & identity | `DisableTactics` | `bool` | Step 5: tactics control |
| Tactics & identity | `TacticsWaitPeriodMilliseconds` | `*int` | Step 5: tactics wait tuning |
| Tactics & identity | `TacticsRetryPeriodMilliseconds` | `*int` | Step 5: tactics retry tuning |
| Tactics & identity | `TacticsTimeoutMilliseconds` | `*int` | Step 5: tactics timeout tuning |

---

## 2. Tunnel-Core Notice Types

### 2.1 VERIFIED IN PINNED CODEBASE (`psi.go:onNotice`, `probe.go`)

| `noticeType` | Key payload fields used | Current PsiRoute Handling |
|---|---|---|
| `Tunnels` | `count` (int) | `psi.go:966` — connected/disconnected state transition |
| `EstablishTunnelTimeout` | — | `psi.go:1008` — returns `errTimeout` |
| `Exiting` | — | `psi.go:1010` — controller exit |
| `AvailableEgressRegions` | `regions` (`[]string`) | `psi.go:1845` |
| `ClientRegion` | `region` (`string`) | `psi.go:1848` |
| `ConnectedServerRegion` | `serverRegion` (`string`) | `psi.go:1851` |
| `ActiveTunnel` | `protocol`, `diagnosticID` | `psi.go:1854`, `probe.go:123` |
| `ConnectingServer` | `diagnosticID` | `psi.go:1863` |
| `CandidateServers` | `count` (int) | `psi.go:1871` |
| `RemoteServerListResourceDownloaded` | — | `psi.go:1884` |
| `RemoteServerListResourceDownloadFailed` | — | `psi.go:1887` |
| `UpstreamProxyError` | `message` (`string`) | `psi.go:1900` |
| `Warning` | `message` (`string`) | `psi.go:1910` |
| `Error` | `message` (`string`) | `psi.go:1910` |

### 2.2 Additional Notice Types — **NOT VERIFIED** against exact commit `aabc0b3a6397`

Observed in [`pkg.go.dev/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon`](https://pkg.go.dev/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon). Verify exact `noticeType` strings and payload keys in local module cache before wiring into Steps 2–5:

- `ConnectedServer` (protocol, dial params summary)
- `RequestingTactics` / `RequestedTactics` (tactics fetch lifecycle)
- `ApplicationParameters` (emitted when tactics apply parameters; see `Config.SetParameters` in `config.go`)
- `RemoteServerListResourceDownloadedBytes` (in-progress RSL download bytes — useful in Step 3 to avoid aborting an active RSL download)
- `LivenessTest` (tunnel liveness check metrics)
- `Fragmentor` (fragmentor activation diagnostics)
- `HoldOffTunnel` (protocol/provider hold-off notice)
- `SkipServerEntry` / `PruneServerEntry` (candidate filtering diagnostics)
- `ServerTimestamp` (server-observed UTC timestamp — useful for clock skew detection)
- `Info` (includes `"applied ... parameters with tag '...'"` when tactics are applied)

---

## 3. Local Verification Commands (Windows, Go 1.26.2)

Run these in the PsiRoute repo directory to verify Tier B fields and notice strings against the exact pinned module cache (`aabc0b3a6397`):

```powershell
# 1. Inspect psiphon.Config struct in the pinned module cache
go doc github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.Config

# 2. List all Notice* functions in the pinned module cache
go doc github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon | Select-String "func Notice"

# 3. Inspect exact noticeType string literals in notice.go
$mod = (go list -m -f "{{.Dir}}" github.com/Psiphon-Labs/psiphon-tunnel-core)
Select-String -Path "$mod\psiphon\notice.go" -Pattern 'outputNotice\('
```
