// Package mesh manages the mesh network state: known peers, their liveness,
// and the overall topology.
package mesh

import (
	"log/slog"
	"sync"
	"time"
)

// PeerState tracks what we know about a remote peer.
type PeerState struct {
	PublicKey   string
	VirtualIP   string // optional: internal mesh IP
	Endpoints   []string
	LastSeen    time.Time
	Latency     time.Duration
	IsConnected bool
	SoftwareVer string
}

// Event describes a change in mesh state that listeners should react to.
type Event struct {
	Type    EventType
	Peer    string // public key
	Message string
}

type EventType int

const (
	EventPeerJoined EventType = iota
	EventPeerLeft
	EventPeerUpdated
)

// State is the central mesh peer registry.
type State struct {
	mu    sync.RWMutex
	peers map[string]*PeerState
	self  *PeerState
	log   *slog.Logger
}

func NewState(selfKey string) *State {
	return &State{
		peers: make(map[string]*PeerState),
		self: &PeerState{
			PublicKey: selfKey,
			LastSeen:  time.Now(),
		},
		log: slog.With("module", "mesh"),
	}
}

func (s *State) Self() *PeerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.self
}

func (s *State) UpsertPeer(pk string, update func(*PeerState)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.peers[pk]
	if !ok {
		p = &PeerState{PublicKey: pk}
		s.peers[pk] = p
	}
	update(p)
	p.LastSeen = time.Now()
}

func (s *State) RemovePeer(pk string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.peers, pk)
}

func (s *State) GetPeer(pk string) *PeerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peers[pk]
}

// Peers returns a snapshot of all known peers.
func (s *State) Peers() map[string]*PeerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string]*PeerState, len(s.peers))
	for k, v := range s.peers {
		cp[k] = v
	}
	return cp
}

// ConnectedPeers returns peers that are currently reachable.
func (s *State) ConnectedPeers() []*PeerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*PeerState
	for _, p := range s.peers {
		if p.IsConnected {
			out = append(out, p)
		}
	}
	return out
}

// PeerCount returns total and connected counts.
func (s *State) PeerCount() (total, connected int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.peers {
		total++
		if p.IsConnected {
			connected++
		}
	}
	return
}
