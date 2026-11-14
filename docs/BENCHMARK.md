# Performance Benchmarks

## Methodology

Benchmarks are reproducible and measure the actual binary under controlled
conditions. No results are faked or hardcoded.

Test harness:
- `cargo bench` (criterion) for micro-benchmarks of SMTP parsing and queue ops.
- A local mock SMTP server for end-to-end relay delivery benchmarks.
- `wrk`-style concurrent connection sweeps for connection-handling capacity.
- `/usr/bin/time -v` and `valgrind massif` for RSS/allocation measurements.

Conditions must be documented per run: CPU, kernel, Rust version, profile
(release vs debug), config values (max_connections, max_message_size), and
whether TLS is enabled.

## Engineering targets (not measurements)

These are design targets, not claimed results:

| Metric | Target |
|--------|--------|
| Idle RSS | 2–5 MB |
| RSS under light load | 5–15 MB |
| Connections per second | limited only by epoll/backlog |
| SMTP transactions/sec | hardware-dependent |
| Max unbounded growth | none (bounded queues, streaming) |

## How to run

```bash
# Micro-benchmarks (SMTP parsing, queue encode/decode)
cargo bench

# End-to-end: start a mock upstream, run rmtp, measure delivery throughput
./scripts/bench-relay.sh

# Memory: run under massif, capture peak RSS
valgrind --tool=massif target/release/rustsmtp start --config rmtp.toml
```

## Recording results

Add results to this file only after running the harness, including the date,
hardware, and configuration used. Example format:

```
2026-11-14 | x86_64, 2 vCPU, 3.8 GiB RAM | release | no TLS
  idle RSS:        MB  (target 2–5)
  50 concurrent conns RSS: MB  (target 5–15)
  deliveries/sec:   #
```
