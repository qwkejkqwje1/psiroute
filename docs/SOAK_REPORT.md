# Step 7 — 24h Simulated Soak & Regression Report

> **Это ускоренная симуляция (виртуальные часы, без сети), а не полевой 24-часовой тест.**
> Она проверяет логику восстановления и ограниченность ресурсов, но ничего не говорит о
> реальных сетях. Полевой прогон на домашнем провайдере и LTE/5G — отдельно, в `docs/FIELD_TESTS.md`.

## Scenario Covered (`psi_soak_test.go:TestStep7_Soak24hSimulatedFlapsSleepResumeAndDNSChanges`)
- **Simulated duration**: 24 hours (144 ticks × 10 min virtual clock via injectable `preflightProbes.Now`).
- **Injected fault cycles (every 2 simulated hours)**:
  1. Network interface switch (`net-home-0` → `net-lte-*`) + preflight cache invalidation.
  2. Sleep/resume invalidation and fresh Stage 0 preflight.
  3. ISP DNS poisoning (`10.10.34.35` vs DoH `52.216.10.1`).
  4. ~16 KB TSPU throttle on `direct` carrier with healthy `warp` fallback.
  5. Full network recovery back to healthy `direct`.
- **Assertions enforced by the test**:
  - Recovery time per flap/resume/DNS change `<= 60 s`.
  - Bounded `connTimeline` ring buffer (`<= 128` events).
  - Non-empty carrier ranking and responsive `connectionStateView()` on every tick (no stuck state / deadlock).
  - Goroutine growth bounded (`<= 20` delta after `runtime.GC()`).

## Execution Status
- **NOT VERIFIED LOCALLY**: This environment has no Go compiler installed. Run on Windows (Go 1.26.2):
  ```powershell
  go test -v -race -count=1 -run TestStep7_Soak24hSimulatedFlapsSleepResumeAndDNSChanges ./...
  ```
- **NOT VERIFIED IN REAL NETWORK**: Real 24h soak on Russian home ISP and mobile LTE/5G networks must be recorded in `docs/FIELD_TESTS.md`.
