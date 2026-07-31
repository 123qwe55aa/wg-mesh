# NAT Traversal Design Notes

## Hole punching feasibility by NAT pair (corrected)

> Original claim "zero prediction for NAT3↔NAT4 when NAT4 initiates" was
> imprecise. STUN port ≠ punchable port. Breakdown below.

### Why a STUN port is not directly punchable

1. **NAT4 (symmetric): mapping is per-destination.** The port STUN observes
   is the mapping *toward the STUN server only*. The mapping toward any other
   destination (e.g. a NAT3 peer) will be a different port. NAT4 itself does
   not know what port it will assign for that peer until it sends.
2. **NAT3 (EIM): the STUN port *is* valid for other destinations**, but has
   caveats: mapping aging (UDP timeout), port-reuse risk, and
   port-restricted filtering requires "warming up" (the peer must send first)
   before inbound is accepted.
3. **Timing**: packets are dropped before the mapping is established;
   misaligned retransmit windows fail even with correct ports.

### Corrected feasibility matrix

| Pair | Prediction needed | Notes |
|------|-------------------|-------|
| NAT3 ↔ NAT3 | **None** | STUN ports are stable across destinations; warm up one round, then direct. |
| NAT4 → NAT3 | **One direction only** | Destination port = NAT3's STUN port (stable, known) → no guessing on the cone side. NAT4's *source* port P_B is still unknown, but has a strong prior: port-preserving symmetric NAT gives P_B ≈ local port; otherwise predictable from local socket allocation. |
| NAT4 ↔ NAT4 | **Both directions + timing sync** | Hardest case; this is the real algorithmic challenge. |

### Recommended implementation: NAT4-initiated punch toward NAT3

- Symmetric side: bind a **fixed local port** → send actively → use the
  local port as the external-port prior (port-preserving NAT4).
- Cone side: the NAT4 peer advertises its predicted P_B; the cone side
  **warms up a small candidate-port range** (a few ports around the prior)
  so the port-restricted filter accepts the reply.
- The two cooperate: one-sided prediction + range warm-up beats blind
  two-sided prediction.

## Implemented: symmetric NAT port prediction (`--port-predict`)

- `pkg/nat/predict.go` — `PortPredictor`: probes the NAT's port-allocation
  delta on the real WG port (SO_REUSEPORT, same mapping family as the WG
  socket) across multiple STUN targets, derives the step, and registers the
  PREDICTED next port as the DHT public endpoint.
- Refresh every 60s (mapping counter drifts; other traffic advances it).
- Caveat: probing ports are ephemeral — prediction is a window, not a
  guarantee. See `pkg/nat/predict_test.go` for the edge cases handled
  (unstable delta → abandon, zero delta = cone → abandon, wrap-around → 0).
