// Package nat: Symmetric NAT port prediction.
//
// A symmetric NAT (NAT4) assigns a NEW external port for every distinct
// (destination IP, port) tuple. The assignment is often sequential with a
// constant delta (e.g. +2). If we can measure that delta, we can predict
// the port the NAT will assign for a future target — which is exactly what
// hole punching needs: tell the peer "reply to this predicted port" before
// the real traffic creates the mapping.
//
// The measured ports are only valid for a short window (the probing
// connections time out and other traffic advances the NAT counter), so the
// predictor must be re-probed periodically.
package nat

import (
	"fmt"
	"log/slog"
	"net"
	"time"
)

// PortPredictor samples the external ports a NAT assigns across multiple
// distinct destinations and derives the allocation delta.
type PortPredictor struct {
	stunAddrs []string // probe targets (rotated to force new NAT mappings)
	conn      *net.UDPConn
	samples   []int
	step      int // constant delta between consecutive mappings, 0 = unknown/random
	probeIdx  int // round-robin index into stunAddrs
	lastProbe time.Time
}

// NewPortPredictor creates a predictor using conn as the probe socket.
// The same socket must be used for all probes: this mirrors the WG socket
// behavior and keeps the NAT mapping family consistent. stunAddrs is a
// comma-separated list of probe targets; consecutive probes rotate through
// them so the NAT assigns a fresh mapping each time (required for symmetric
// NAT delta measurement).
func NewPortPredictor(stunAddrs string, conn *net.UDPConn) *PortPredictor {
	var addrs []string
	for _, s := range splitList(stunAddrs) {
		if s != "" {
			addrs = append(addrs, s)
		}
	}
	if len(addrs) == 0 {
		addrs = []string{defaultStunServer}
	}
	return &PortPredictor{
		stunAddrs: addrs,
		conn:      conn,
		step:      0,
	}
}

func splitList(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' || r == ' ' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
		} else {
			cur += string(r)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// Probe sends one STUN binding request to the next probe target and records
// the external port the NAT assigned for that (destination) tuple.
func (p *PortPredictor) Probe() error {
	if p.conn == nil {
		return fmt.Errorf("probe conn is nil")
	}
	// Rotate targets so each probe hits a distinct destination, forcing a
	// fresh symmetric-NAT mapping (needed to measure the allocation delta).
	addr := p.stunAddrs[p.probeIdx%len(p.stunAddrs)]
	p.probeIdx++
	serverAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("stun resolve %s: %w", addr, err)
	}

	req := buildStunRequest()
	p.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := p.conn.WriteToUDP(req, serverAddr); err != nil {
		return fmt.Errorf("stun write: %w", err)
	}

	buf := make([]byte, 1024)
	p.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := p.conn.ReadFromUDP(buf)
	if err != nil {
		return fmt.Errorf("stun read: %w", err)
	}

	res := parseStunResponse(buf[:n])
	if res.PublicPort == 0 {
		return fmt.Errorf("stun response has no mapped port")
	}
	p.samples = append(p.samples, res.PublicPort)
	p.lastProbe = time.Now()
	slog.Debug("nat port probe", "external_port", res.PublicPort, "nat_type", res.NATType)
	return nil
}

// Analyze derives the allocation step from the collected samples.
// Requires at least 2 samples. Returns true if a stable delta was found.
func (p *PortPredictor) Analyze() bool {
	if len(p.samples) < 2 {
		p.step = 0
		return false
	}
	// Compute deltas between consecutive samples
	firstDelta := p.samples[1] - p.samples[0]
	stable := true
	for i := 2; i < len(p.samples); i++ {
		if p.samples[i]-p.samples[i-1] != firstDelta {
			stable = false
			break
		}
	}
	if !stable || firstDelta == 0 {
		// 0 delta means the NAT reuses one port (EIM/cone) — not symmetric
		p.step = 0
		return false
	}
	p.step = firstDelta
	slog.Info("nat port allocation detected",
		"samples", p.samples,
		"step", p.step,
		"predictable", true,
	)
	return true
}

// Predict returns the external port the NAT will likely assign for the next
// distinct destination, based on the last observed sample and the step.
// Returns 0 when not predictable.
func (p *PortPredictor) Predict() int {
	if p.step == 0 || len(p.samples) == 0 {
		return 0
	}
	next := p.samples[len(p.samples)-1] + p.step
	// Guard against wrapping out of the ephemeral range (32768-60999 typical)
	if next > 65535 || next < 1024 {
		return 0
	}
	return next
}

// PredictForTarget estimates the port the NAT will assign for a NEW target
// given that `probes` new distinct destinations will be created between now
// and the punch attempt. This is inherently fuzzy; offset is usually 1.
func (p *PortPredictor) PredictForTarget(offset int) int {
	if p.step == 0 || len(p.samples) == 0 {
		return 0
	}
	next := p.samples[len(p.samples)-1] + p.step*offset
	if next > 65535 || next < 1024 {
		return 0
	}
	return next
}

// Reset clears collected samples (call before a fresh probe round).
func (p *PortPredictor) Reset() {
	p.samples = nil
	p.step = 0
}

// LastSample returns the most recent observed external port.
func (p *PortPredictor) LastSample() int {
	if len(p.samples) == 0 {
		return 0
	}
	return p.samples[len(p.samples)-1]
}

// Predictable reports whether a stable allocation delta was measured.
func (p *PortPredictor) Predictable() bool { return p.step != 0 }

// Step returns the measured allocation delta.
func (p *PortPredictor) Step() int { return p.step }
