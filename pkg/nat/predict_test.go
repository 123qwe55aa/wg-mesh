package nat

import (
	"net"
	"testing"
)

// helper: build a predictor with injected samples (bypasses network probe)
func predictorWithSamples(samples []int) *PortPredictor {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	p := NewPortPredictor("stun.a:3478,stun.b:3478", conn)
	p.samples = append(p.samples, samples...)
	return p
}

func TestAnalyzeSequentialStep(t *testing.T) {
	p := predictorWithSamples([]int{40000, 40002, 40004})
	if !p.Analyze() {
		t.Fatal("expected predictable allocation for +2 step")
	}
	if p.Step() != 2 {
		t.Fatalf("expected step 2, got %d", p.Step())
	}
	if got := p.Predict(); got != 40006 {
		t.Fatalf("expected predict 40006, got %d", got)
	}
	if got := p.PredictForTarget(1); got != 40006 {
		t.Fatalf("expected predictForTarget(1) 40006, got %d", got)
	}
	if got := p.PredictForTarget(2); got != 40008 {
		t.Fatalf("expected predictForTarget(2) 40008, got %d", got)
	}
}

func TestAnalyzeStepOne(t *testing.T) {
	p := predictorWithSamples([]int{40000, 40001, 40002})
	if !p.Analyze() {
		t.Fatal("expected predictable allocation for +1 step")
	}
	if p.Step() != 1 {
		t.Fatalf("expected step 1, got %d", p.Step())
	}
	if got := p.Predict(); got != 40003 {
		t.Fatalf("expected predict 40003, got %d", got)
	}
}

func TestAnalyzeUnstableDelta(t *testing.T) {
	p := predictorWithSamples([]int{40000, 40002, 40005}) // deltas: +2, +3
	if p.Analyze() {
		t.Fatal("expected NOT predictable for unstable deltas")
	}
	if p.Predictable() {
		t.Fatal("Predictable() should be false after unstable Analyze")
	}
	if got := p.Predict(); got != 0 {
		t.Fatalf("expected predict 0 for unstable, got %d", got)
	}
}

func TestAnalyzeZeroDeltaIsCone(t *testing.T) {
	p := predictorWithSamples([]int{40000, 40000, 40000}) // reused port = EIM/cone
	if p.Analyze() {
		t.Fatal("zero delta (reused port) must NOT be treated as symmetric")
	}
	if p.Predictable() {
		t.Fatal("cone NAT must not be predictable")
	}
}

func TestAnalyzeNeedsTwoSamples(t *testing.T) {
	p := predictorWithSamples([]int{40000})
	if p.Analyze() {
		t.Fatal("single sample must not be analyzable")
	}
	if got := p.Predict(); got != 0 {
		t.Fatalf("expected 0 with one sample, got %d", got)
	}
}

func TestPredictOutOfRange(t *testing.T) {
	p := predictorWithSamples([]int{65534, 65535}) // step +1 wraps past 65535
	if !p.Analyze() {
		t.Fatal("expected analyzable")
	}
	if got := p.Predict(); got != 0 {
		t.Fatalf("expected 0 for wrap-around prediction, got %d", got)
	}
}

func TestResetClearsState(t *testing.T) {
	p := predictorWithSamples([]int{40000, 40001})
	p.Analyze()
	if !p.Predictable() {
		t.Fatal("precondition: should be predictable")
	}
	p.Reset()
	if p.Predictable() {
		t.Fatal("Predictable() must be false after Reset")
	}
	if p.LastSample() != 0 {
		t.Fatal("LastSample must be 0 after Reset")
	}
}

func TestSplitList(t *testing.T) {
	got := splitList("a:1, b:2 ,c:3")
	if len(got) != 3 || got[0] != "a:1" || got[1] != "b:2" || got[2] != "c:3" {
		t.Fatalf("unexpected split: %v", got)
	}
	if len(splitList("")) != 0 {
		t.Fatal("empty input should produce empty list")
	}
}
