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
	"strconv"
	"sync"
	"time"
)

const (
	kBuckets    = 160
	kBucketSize = 8
	kParallel   = 3
)

type Contact struct {
	ID              string
	PublicKey       string
	Endpoint        string
	PublicEndpoint  string // STUN-discovered public address (for NAT traversal)
	ControlEndpoint string // DHT TCP address; distinct from the WG UDP endpoint
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
	table            *Table
	publicKey        string
	wgEndpoint       string  // this node's WireGuard endpoint (ip:port)
	publicEndpoint   string  // this node's STUN-discovered public address (ip:port), for NAT traversal
	seedContact      Contact // first seed contact, used for peer state reporting
	listener         net.Listener
	log              *slog.Logger
	stopCh           chan struct{}
	onPeerDiscovered func(Contact) // callback when new peer discovered via DHT
	onPunchPlan      func(DhtMessage)
	controlMu        sync.Mutex
	controlConns     map[string]net.Conn
	// observedEndpoint returns the endpoint currently observed by the local
	// WireGuard device. The hub uses this to replace a peer's self-reported
	// endpoint (which may be a STUN guess).
	observedEndpoint func(publicKey string) string
}

const (
	MsgFindNode = iota
	MsgFindNodeResp
	MsgPing
	MsgPong
	MsgReportState
	MsgPunchPlan
	MsgControlHello
)

type DhtMessage struct {
	Type            uint8
	SenderID        string
	TargetID        string
	Contacts        []Contact
	PublicKey       string // sender's WireGuard public key
	WgEndpoint      string // sender's WireGuard endpoint (ip:port)
	PublicEndpoint  string // sender's STUN-discovered public address (ip:port)
	State           string // peer connection state: "p2p", "relay", "disconnected"
	ControlEndpoint string // sender's reachable DHT TCP address
	PunchID         string
	TargetPublicKey string
	PunchStartUnix  int64
	PunchWindowMs   int
	PunchPorts      []string
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
		table:        table,
		publicKey:    publicKey,
		wgEndpoint:   wgEndpoint,
		listener:     l,
		log:          slog.With("module", "dht"),
		stopCh:       make(chan struct{}),
		controlConns: make(map[string]net.Conn),
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

// SetPunchPlanCallback registers the synchronized punch-plan handler. The
// callback must only prepare the local WG endpoint; the actual attempt should
// begin at PunchStartUnix and remain relay-safe until a real handshake arrives.
func (d *DHT) SetPunchPlanCallback(fn func(DhtMessage)) {
	d.onPunchPlan = fn
}

// OpenControl keeps a node-initiated TCP control channel open to the peer.
// The peer can then send PunchPlan messages back without dialing through NAT.
func (d *DHT) OpenControl(contact Contact) error {
	addr := contact.ControlEndpoint
	if addr == "" {
		addr = contact.Endpoint
	}
	if addr == "" {
		return fmt.Errorf("control: empty endpoint")
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	if err := gob.NewEncoder(conn).Encode(DhtMessage{Type: MsgControlHello, SenderID: d.table.selfID, PublicKey: d.publicKey}); err != nil {
		conn.Close()
		return err
	}
	go func() {
		dec := gob.NewDecoder(conn)
		for {
			var msg DhtMessage
			if err := dec.Decode(&msg); err != nil {
				conn.Close()
				return
			}
			if msg.Type == MsgPunchPlan && d.onPunchPlan != nil {
				d.onPunchPlan(msg)
			}
		}
	}()
	return nil
}

func (d *DHT) SetObservedEndpoint(fn func(publicKey string) string) {
	d.observedEndpoint = fn
}

// SetPublicEndpoint updates the DHT with the STUN-discovered public address.
// This is called after STUN discovery completes, so subsequent findNode
// requests include the public endpoint for cross-NAT P2P connectivity.
func (d *DHT) SetPublicEndpoint(ep string) {
	d.publicEndpoint = ep
	d.log.Info("dht public endpoint set", "ep", ep)
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
	dec := gob.NewDecoder(conn)
	var msg DhtMessage
	if err := dec.Decode(&msg); err != nil {
		d.log.Warn("dht decode", "from", conn.RemoteAddr(), "error", err)
		return
	}
	switch msg.Type {
	case MsgControlHello:
		if msg.PublicKey != "" {
			d.controlMu.Lock()
			d.controlConns[msg.PublicKey] = conn
			d.controlMu.Unlock()
		}
		// Keep this connection open; the peer owns the writer side.
		select {
		case <-d.stopCh:
		case <-time.After(24 * time.Hour):
		}
		return
	case MsgFindNode:
		d.handleFindNode(conn, &msg)
	case MsgPing:
		d.handlePing(conn)
	case MsgReportState:
		d.handleReportState(&msg)
	case MsgPunchPlan:
		if d.onPunchPlan != nil {
			d.onPunchPlan(msg)
		}
	}
}

// SendPunchPlan sends the same future start time and candidate-port window to
// a peer over the existing DHT control channel. The caller should send the
// identical plan to both participants; start time is Unix milliseconds.
func (d *DHT) SendPunchPlan(contact Contact, targetPublicKey, targetEndpoint, punchID string, start time.Time, window time.Duration, ports []string) error {
	d.controlMu.Lock()
	conn := d.controlConns[contact.PublicKey]
	d.controlMu.Unlock()
	if conn != nil {
		msg := DhtMessage{Type: MsgPunchPlan, SenderID: d.table.selfID, PublicKey: d.publicKey, TargetPublicKey: targetPublicKey, WgEndpoint: targetEndpoint, PunchID: punchID, PunchStartUnix: start.UnixMilli(), PunchWindowMs: int(window / time.Millisecond), PunchPorts: append([]string(nil), ports...)}
		return gob.NewEncoder(conn).Encode(msg)
	}
	control := contact.ControlEndpoint
	if control == "" {
		control = contact.Endpoint
	}
	if control == "" {
		return fmt.Errorf("punch plan: empty peer endpoint")
	}
	conn, err := net.DialTimeout("tcp", control, 5*time.Second)
	if err != nil {
		return fmt.Errorf("punch plan connect: %w", err)
	}
	defer conn.Close()
	msg := DhtMessage{
		Type:            MsgPunchPlan,
		SenderID:        d.table.selfID,
		PublicKey:       d.publicKey,
		PunchID:         punchID,
		TargetPublicKey: targetPublicKey,
		WgEndpoint:      targetEndpoint,
		PunchStartUnix:  start.UnixMilli(),
		PunchWindowMs:   int(window / time.Millisecond),
		PunchPorts:      append([]string(nil), ports...),
	}
	if err := gob.NewEncoder(conn).Encode(msg); err != nil {
		return fmt.Errorf("punch plan encode: %w", err)
	}
	return nil
}

func (d *DHT) handleFindNode(conn net.Conn, msg *DhtMessage) {
	ep := msg.WgEndpoint
	if ep == "" {
		// fallback: use the TCP connection address (DHT port, not ideal)
		ep = conn.RemoteAddr().String()
	}
	contact := Contact{
		ID:              msg.SenderID,
		PublicKey:       msg.PublicKey,
		Endpoint:        ep,
		PublicEndpoint:  msg.PublicEndpoint,
		ControlEndpoint: msg.ControlEndpoint,
	}
	if d.observedEndpoint != nil {
		if observed := d.observedEndpoint(msg.PublicKey); observed != "" {
			contact.PublicEndpoint = observed
		}
	}
	d.table.insert(contact)
	// Fire callback on the responder side (hub) so peer registrations are visible
	if d.onPeerDiscovered != nil && msg.PublicKey != "" && msg.PublicKey != d.publicKey {
		d.log.Info("dht hub registered peer update",
			"pk", msg.PublicKey[:16],
			"ep", ep,
			"public_ep", msg.PublicEndpoint,
		)
		d.onPeerDiscovered(contact)
	}
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
				d.log.Info("dht discovered peer",
					"id", c.ID[:8],
					"pk", c.PublicKey[:16],
					"ep", c.Endpoint,
					"public_ep", c.PublicEndpoint,
				)
			} else {
				d.log.Debug("dht discovered peer (incomplete)",
					"id", c.ID[:8],
					"ep", c.Endpoint,
					"public_ep", c.PublicEndpoint,
				)
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

// handleReportState logs a peer state report received from another peer.
// The state indicates the peer's connection status: "p2p", "relay", or "disconnected".
func (d *DHT) handleReportState(msg *DhtMessage) {
	if len(msg.SenderID) >= 8 && len(msg.TargetID) >= 8 {
		d.log.Info("dht peer state report",
			"from", msg.SenderID[:8],
			"peer", msg.TargetID[:8],
			"state", msg.State,
			"endpoint", msg.WgEndpoint,
		)
	} else {
		d.log.Info("dht peer state report",
			"from", msg.SenderID,
			"peer", msg.TargetID,
			"state", msg.State,
			"endpoint", msg.WgEndpoint,
		)
	}
}

func (d *DHT) Bootstrap(seeds []Contact) {
	for _, seed := range seeds {
		if len(seed.ID) >= 8 {
			d.log.Info("dht bootstrap to seed", "id", seed.ID[:8], "ep", seed.Endpoint)
		} else {
			d.log.Info("dht bootstrap to seed", "id", seed.ID, "ep", seed.Endpoint)
		}
		d.table.insert(seed)
		// Store first seed for state reporting
		if d.seedContact.PublicKey == "" {
			d.seedContact = seed
		}
		d.findNode(d.table.selfID, seed)
	}
}

// SendState reports a peer connection state to the hub/seed.
// Called when a peer's connection status changes (p2p, relay, disconnected).
func (d *DHT) SendState(peerPubKey, state, endpoint string) {
	if d.seedContact.PublicKey == "" {
		d.log.Debug("dht send_state skipped: no seed contact")
		return
	}
	peerID := NodeID(peerPubKey)
	msg := DhtMessage{
		Type:       MsgReportState,
		SenderID:   d.table.selfID,
		TargetID:   peerID,
		PublicKey:  d.publicKey,
		WgEndpoint: endpoint,
		State:      state,
	}
	conn, err := net.DialTimeout("tcp", d.seedContact.Endpoint, 10*time.Second)
	if err != nil {
		d.log.Warn("dht send_state connect failed", "error", err)
		return
	}
	defer conn.Close()
	enc := gob.NewEncoder(conn)
	if err := enc.Encode(msg); err != nil {
		d.log.Warn("dht send_state encode failed", "error", err)
		return
	}
	d.log.Debug("dht state sent",
		"peer", peerID[:8],
		"state", state,
		"ep", endpoint,
	)
}

func (d *DHT) findNode(targetID string, contact Contact) {
	conn, err := net.DialTimeout("tcp", contact.Endpoint, 10*time.Second)
	if err != nil {
		d.log.Warn("dht find_node connect failed", "ep", contact.Endpoint, "error", err)
		return
	}
	defer conn.Close()

	msg := DhtMessage{
		Type:           MsgFindNode,
		SenderID:       d.table.selfID,
		TargetID:       targetID,
		PublicKey:      d.publicKey,
		WgEndpoint:     d.wgEndpoint,
		PublicEndpoint: d.publicEndpoint,
	}
	// Advertise the DHT TCP address separately from the WireGuard UDP endpoint.
	// A TCP connection's RemoteAddr is an ephemeral client port and cannot be
	// used by the hub to send a later punch plan.
	if _, host, err := net.SplitHostPort(d.publicEndpoint); err == nil && host != "" {
		if tcpAddr, ok := d.listener.Addr().(*net.TCPAddr); ok {
			msg.ControlEndpoint = net.JoinHostPort(host, strconv.Itoa(tcpAddr.Port))
		}
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

// Refresh re-queries the DHT for all known peers.
// This picks up endpoint changes from peers that re-registered with new addresses.
// Call periodically (e.g., every 5 minutes) from the main loop.
func (d *DHT) Refresh() {
	d.log.Debug("dht refresh started")
	for _, contact := range d.KnownPeers() {
		// Skip self
		if contact.PublicKey == "" || contact.PublicKey == d.publicKey {
			continue
		}
		// Re-query for our own ID through a known contact (usually the hub)
		// The hub returns the latest contacts including any updated endpoints
		d.findNode(d.table.selfID, contact)
	}
	d.log.Debug("dht refresh completed")
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
	for i, existing := range bucket.contacts {
		if existing.ID == c.ID {
			// Update existing contact with latest endpoint info
			bucket.contacts[i].Endpoint = c.Endpoint
			if c.PublicEndpoint != "" {
				bucket.contacts[i].PublicEndpoint = c.PublicEndpoint
			}
			t.log.Debug("dht updated contact",
				"id", c.ID[:8],
				"ep", c.Endpoint,
				"public_ep", c.PublicEndpoint,
			)
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
