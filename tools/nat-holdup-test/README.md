# NAT hole-punching test tools

Verify your NAT type and mapping behavior before trusting hole punching.
These are standalone Python scripts — no build needed.

## Components

| Script | Where to run | What it verifies |
|--------|-------------|------------------|
| `nat3_test.py` | Behind the suspected NAT3 (e.g. home CGNAT) | EIM port hold: 5× STUN + punch packets to hub, all from same local socket → hub-observed source port must stay identical to the STUN port |
| `nat4_test.py` | Behind the suspected NAT4 (e.g. outdoor WiFi) | Per-destination mapping: same socket probing multiple STUN targets → distinct external ports = ADM/APDM (NAT4); also checks whether allocation is sequential (predictable) or randomized |
| `echo_server.py` | On the hub (public IP) | UDP echo server used by `nat3_test.py` (port 52222) so the client can observe the hub's view of its source port |

## Quick start

```bash
# 1. On the hub (public IP, e.g. 175.178.118.76):
python3 echo_server.py 52222

# 2. Behind the NAT under test:
python3 nat3_test.py   # NAT3 check (needs hub echo server)
python3 nat4_test.py   # NAT4 check (needs only STUN reachability)
```

## Reading the results

`nat3_test.py` output:

```
[stun] 端口保持: True (distinct=[46481])   ← EIM confirmed: one port for all
[punch#0] hub reply: b'ECHO:46481:...'      ← hub saw the SAME port
```

- Port hold `True` + hub echo matches → NAT3 (EIM), hole punching viable
  against another EIM peer with STUN-disclosed ports.

`nat4_test.py` output:

```
[mapping] distinct external ports across targets: [3245, 17347]  → NAT4
[predict] no stable delta → allocation RANDOMIZED, prediction NOT feasible
```

- Distinct ports per target → NAT4 (symmetric). Sequential deltas would
  make `--port-predict` (pkg/nat/predict.go) viable; randomized means
  blind multi-port probing or relay only.

## Field results (2026-07, Shenzhen)

- **Home (China Unicom CGNAT, via Lisa)**: EIM confirmed. Port held at
  163.125.134.99:46481 across 5 STUN + 3 punch packets; mapping timeout
  > 75s of silence. → **NAT3**.
- **Outdoor WiFi (via Toby)**: per-destination ports (3245 / 17347),
  no sequential delta. → **NAT4 randomized**.
