// Package dht implements a Kademlia-style DHT for peer discovery over TCP.
package dht

import (
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/bits"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	kBuckets    = 160
	kBucketSize = 8
	kParallel   = 3
)

type Contact struct {
	ID        string
	PublicKey string
	Endpoint  string
}

func NodeID(publicKey string) string {
	h := sha256.Sum256([]byte(publicKey))
	return hex.EncodeToString(h[:20])
}

func xorDist(a, b string) []byte {
	da, _ := hex.DecodeString(a)
	db, _ := hex.DecodeString(b)
	out := make([]byte, len(da))
	for i := range da {
		out[i] = da[i] ^ db[i]
	}
	return out
}

func leadingZeros(dist []byte) int {
	for i, b := range dist {
		if b != 0 {
			return i*8 + bits.LeadingZeros8(b)
		}
	}
	return len(dist) * 8
}

type KBucket struct {
	mu       sync.Mutex
	contacts []Contact
}

type Table struct {
	mu      sync.RWMutex
	selfID  string
	buckets [kBuckets]*KBucket
	log     *slog.Logger
}

type DHT struct {
	table     *Table
	publicKey string
	wgEndpoint string // this node's WireGuard endpoint (ip:port)
	listener  net.Listener
	log       *slog.Logger
	stopCh    chan struct{}
	onPeerDiscovered func(Contact) // callback when new peer discovered via DHT
}

const (
	MsgFindNode = iota
	MsgFindNodeResp
	MsgPing
	MsgPong
)

type DhtMessage struct {
	Type       uint8
	SenderID   string
	TargetID   string
	Contacts   []Contact
	PublicKey  string // sender's WireGuard public key
	WgEndpoint string // sender's WireGuard endpoint (ip:port)
}

func NewDHT(publicKey string, listenPort int, wgEndpoint string) (*DHT, error) {
	l, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", listenPort))
	if err != nil {
		return nil, fmt.Errorf("dht listen: %w", err)
	}
	selfID := NodeID(publicKey)
	table := &Table{
		selfID:  selfID,
		buckets: [kBuckets]*KBucket{},
		log:     slog.With("module", "dht"),
	}
	for i := range table.buckets {
		table.buckets[i] = &KBucket{}
	}
	return &DHT{
		table:      table,
		publicKey:  publicKey,
		wgEndpoint: wgEndpoint,
		listener:   l,
		log:        slog.With("module", "dht"),
		stopCh:     make(chan struct{}),
	}, nil
}

func (d *DHT) ListenPort() int {
	return d.listener.Addr().(*net.TCPAddr).Port
}

func (d *DHT) Start() {
	fmt.Printf("DHT START CALLED\n")
	go d.acceptLoop()
}

func (d *DHT) Stop() {
	close(d.stopCh)
	d.listener.Close()
}

// SetPeerCallback registers a function called when a new peer is discovered.
func (d *DHT) SetPeerCallback(fn func(Contact)) {
	d.onPeerDiscovered = fn
}

func (d *DHT) acceptLoop() {
	fmt.Printf("DHT ACCEPT LOOP ENTERED\n")
	defer fmt.Printf("dht acceptLoop EXITED\n")
	for {
		conn, err := d.listener.Accept()
		if err != nil {
			select {
			case <-d.stopCh:
				fmt.Printf("dht acceptLoop stopped\n")
				return
			default:
				fmt.Printf("dht accept error: %v\n", err)
				continue
			}
		}
		fmt.Printf("dht accepted connection from %s (local=%s)\n", conn.RemoteAddr(), conn.LocalAddr())
		go d.handleConn(conn)
	}
}

func (d *DHT) handleConn(conn net.Conn) {
	defer conn.Close()
	dec := gob.NewDecoder(conn)
	var msg DhtMessage
	if err := dec.Decode(&msg); err != nil {
		d.log.Warn("dht decode", "from", conn.RemoteAddr(), "error", err)
		return
	}
	switch msg.Type {
	case MsgFindNode:
		d.handleFindNode(conn, &msg)
	case MsgPing:
		d.handlePing(conn)
	}
}

func (d *DHT) handleFindNode(conn net.Conn, msg *DhtMessage) {
	ep := msg.WgEndpoint
	if ep == "" {
		// fallback: use the TCP connection address (DHT port, not ideal)
		ep = conn.RemoteAddr().String()
	}
	d.table.insert(Contact{
		ID:        msg.SenderID,
		PublicKey: msg.PublicKey,
		Endpoint:  ep,
	})
	closest := d.table.closest(msg.TargetID, kBucketSize)
	resp := DhtMessage{Type: MsgFindNodeResp, SenderID: d.table.selfID, Contacts: closest}
	enc := gob.NewEncoder(conn)
	enc.Encode(resp)
}

func (d *DHT) handleFindNodeResp(msg *DhtMessage) {
	for _, c := range msg.Contacts {
		if c.ID != d.table.selfID {
			d.table.insert(c)
			if len(c.PublicKey) >= 16 {
				d.log.Info("dht discovered peer", "id", c.ID[:8], "pk", c.PublicKey[:16], "ep", c.Endpoint)
			} else {
				d.log.Debug("dht discovered peer (incomplete)", "id", c.ID[:8], "ep", c.Endpoint)
			}
			if d.onPeerDiscovered != nil && c.PublicKey != "" {
				d.onPeerDiscovered(c)
			}
		}
	}
}

func (d *DHT) handlePing(conn net.Conn) {
	resp := DhtMessage{Type: MsgPong, SenderID: d.table.selfID}
	enc := gob.NewEncoder(conn)
	enc.Encode(resp)
}

func (d *DHT) Bootstrap(seeds []Contact) {
	for _, seed := range seeds {
		if len(seed.ID) >= 8 {
			d.log.Info("dht bootstrap to seed", "id", seed.ID[:8], "ep", seed.Endpoint)
		} else {
			d.log.Info("dht bootstrap to seed", "id", seed.ID, "ep", seed.Endpoint)
		}
		d.table.insert(seed)
		d.findNode(d.table.selfID, seed)
	}
}

func (d *DHT) findNode(targetID string, contact Contact) {
	conn, err := net.DialTimeout("tcp", contact.Endpoint, 10*time.Second)
	if err != nil {
		d.log.Warn("dht find_node connect failed", "ep", contact.Endpoint, "error", err)
		return
	}
	defer conn.Close()

	msg := DhtMessage{
		Type:       MsgFindNode,
		SenderID:   d.table.selfID,
		TargetID:   targetID,
		PublicKey:  d.publicKey,
		WgEndpoint: d.wgEndpoint,
	}
	enc := gob.NewEncoder(conn)
	if err := enc.Encode(msg); err != nil {
		return
	}

	var resp DhtMessage
	dec := gob.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		return
	}
	if resp.Type == MsgFindNodeResp {
		d.handleFindNodeResp(&resp)
	}
}

func (d *DHT) KnownPeers() []Contact {
	d.table.mu.RLock()
	defer d.table.mu.RUnlock()
	var all []Contact
	for _, bucket := range d.table.buckets {
		bucket.mu.Lock()
		all = append(all, bucket.contacts...)
		bucket.mu.Unlock()
	}
	return all
}

func (t *Table) insert(c Contact) {
	dist := xorDist(t.selfID, c.ID)
	bucketIdx := leadingZeros(dist)
	if bucketIdx >= kBuckets {
		return
	}
	bucket := t.buckets[bucketIdx]
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	for _, existing := range bucket.contacts {
		if existing.ID == c.ID {
			return
		}
	}
	if len(bucket.contacts) < kBucketSize {
		bucket.contacts = append(bucket.contacts, c)
	}
}

func (t *Table) closest(targetID string, n int) []Contact {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var candidates []Contact
	for _, bucket := range t.buckets {
		bucket.mu.Lock()
		candidates = append(candidates, bucket.contacts...)
		bucket.mu.Unlock()
	}
	sort.Slice(candidates, func(i, j int) bool {
		di := xorDist(targetID, candidates[i].ID)
		dj := xorDist(targetID, candidates[j].ID)
		return len(di) > 0 && len(dj) > 0 && string(di) < string(dj)
	})
	if len(candidates) > n {
		candidates = candidates[:n]
	}
	return candidates
}
