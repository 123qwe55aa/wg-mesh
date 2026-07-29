// Package pex implements peer exchange (gossip protocol) over TCP.
package pex

import (
	"encoding/gob"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	MsgTypePexRequest = iota
	MsgTypePexResponse
	MsgTypePing
	MsgTypePong
)

type PexMessage struct {
	Type    uint8
	Sender  string
	Entries []PeerEntry
	Seq     uint64
}

type PeerEntry struct {
	PublicKey string
	Endpoints []string
	LatencyMs int
}

type Protocol struct {
	mu         sync.Mutex
	publicKey  string
	entries    map[string]PeerEntry
	knownPeers func() []PeerEntry
	connect    func(publicKey, endpoint string) error
	listenAddr string
	listener   net.Listener
	peers      map[string]net.Conn // connected peers
	seq        uint64
	log        *slog.Logger
	stopCh     chan struct{}
	started    bool
}

func NewProtocol(
	publicKey string,
	listen string,
	knownPeers func() []PeerEntry,
	connect func(publicKey, endpoint string) error,
) (*Protocol, error) {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("pex listen: %w", err)
	}
	return &Protocol{
		publicKey:  publicKey,
		listenAddr: listen,
		listener:   listener,
		entries:    make(map[string]PeerEntry),
		knownPeers: knownPeers,
		connect:    connect,
		peers:      make(map[string]net.Conn),
		log:        slog.With("module", "pex"),
		stopCh:     make(chan struct{}),
	}, nil
}

func (p *Protocol) ListenPort() int {
	return p.listener.Addr().(*net.TCPAddr).Port
}

func (p *Protocol) Start() {
	if p.started {
		return
	}
	p.started = true
	go p.acceptLoop()
	go p.gossipLoop()
}

func (p *Protocol) Stop() {
	close(p.stopCh)
	p.listener.Close()
	for _, conn := range p.peers {
		conn.Close()
	}
}

func (p *Protocol) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.stopCh:
				return
			default:
				continue
			}
		}
		go p.handleConn(conn)
	}
}

func (p *Protocol) handleConn(conn net.Conn) {
	defer conn.Close()
	dec := gob.NewDecoder(conn)
	for {
		var msg PexMessage
		if err := dec.Decode(&msg); err != nil {
			return
		}
		switch msg.Type {
		case MsgTypePexRequest:
			p.handleRequest(conn, &msg)
		case MsgTypePexResponse:
			p.handleResponse(&msg)
		case MsgTypePing:
			p.handlePing(conn)
		default:
		}
	}
}

func (p *Protocol) gossipLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.gossip()
		}
	}
}

func (p *Protocol) gossip() {
	peers := p.knownPeers()
	if len(peers) == 0 {
		return
	}
	p.mu.Lock()
	p.seq++
	seq := p.seq
	p.mu.Unlock()

	msg := PexMessage{
		Type: MsgTypePexRequest, Sender: p.publicKey,
		Entries: peers, Seq: seq,
	}
	for _, peer := range peers {
		for _, ep := range peer.Endpoints {
			go p.sendMessage(ep, &msg)
		}
	}
}

func (p *Protocol) sendMessage(endpoint string, msg *PexMessage) {
	conn, err := net.DialTimeout("tcp", endpoint, 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	enc := gob.NewEncoder(conn)
	enc.Encode(msg)
	// Read response
	var resp PexMessage
	dec := gob.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		return
	}
	if resp.Type == MsgTypePexResponse {
		for _, entry := range resp.Entries {
			if entry.PublicKey == p.publicKey {
				continue
			}
			p.mu.Lock()
			if _, exists := p.entries[entry.PublicKey]; !exists && len(entry.Endpoints) > 0 {
				p.entries[entry.PublicKey] = entry
				p.log.Info("discovered peer via pex", "pk", entry.PublicKey[:16], "ep", entry.Endpoints[0])
				go p.connect(entry.PublicKey, entry.Endpoints[0])
			}
			p.mu.Unlock()
		}
	}
}

func (p *Protocol) handleRequest(conn net.Conn, msg *PexMessage) {
	p.log.Debug("pex request", "entries", len(msg.Entries))
	for _, entry := range msg.Entries {
		if entry.PublicKey == p.publicKey {
			continue
		}
		p.mu.Lock()
		if _, exists := p.entries[entry.PublicKey]; !exists && len(entry.Endpoints) > 0 {
			p.entries[entry.PublicKey] = entry
			go p.connect(entry.PublicKey, entry.Endpoints[0])
		}
		p.mu.Unlock()
	}

	resp := PexMessage{Type: MsgTypePexResponse, Sender: p.publicKey, Entries: p.knownPeers()}
	enc := gob.NewEncoder(conn)
	enc.Encode(resp)
}

func (p *Protocol) handleResponse(msg *PexMessage) {
	for _, entry := range msg.Entries {
		if entry.PublicKey == p.publicKey {
			continue
		}
		p.mu.Lock()
		if _, exists := p.entries[entry.PublicKey]; !exists && len(entry.Endpoints) > 0 {
			p.entries[entry.PublicKey] = entry
			go p.connect(entry.PublicKey, entry.Endpoints[0])
		}
		p.mu.Unlock()
	}
}

func (p *Protocol) handlePing(conn net.Conn) {
	resp := PexMessage{Type: MsgTypePong, Sender: p.publicKey}
	enc := gob.NewEncoder(conn)
	enc.Encode(resp)
}

func (p *Protocol) SendPing(endpoint string) error {
	conn, err := net.DialTimeout("tcp", endpoint, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	msg := PexMessage{Type: MsgTypePing, Sender: p.publicKey}
	return gob.NewEncoder(conn).Encode(msg)
}

func (p *Protocol) DiscoveredPeers() []PeerEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]PeerEntry, 0, len(p.entries))
	for _, e := range p.entries {
		out = append(out, e)
	}
	return out
}
