// wg-meshd is the wg-mesh daemon. It runs alongside wireguard-go as a sidecar,
// managing peer discovery, NAT traversal, and dynamic configuration via uapi.
//
// Architecture:
//
//	┌─────────────┐    uapi (Unix socket)    ┌──────────────┐
//	│ wireguard-go │◄────────────────────────►│   wg-meshd   │
//	│  (dataplane) │                          │  (control)   │
//	└─────────────┘                          └──────┬───────┘
//	                                               │
//	                             ┌─────────────────┼─────────────────┐
//	                             │                 │                 │
//	                         PEX TCP           DHT TCP            STUN
//	                     (peer exchange)   (bootstrap)      (NAT traversal)
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/123qwe55aa/wg-mesh/pkg/dht"
	"github.com/123qwe55aa/wg-mesh/pkg/mesh"
	"github.com/123qwe55aa/wg-mesh/pkg/nat"
	"github.com/123qwe55aa/wg-mesh/pkg/pex"
	"github.com/123qwe55aa/wg-mesh/pkg/uapi"
)

func main() {
	var (
		publicKey   = flag.String("public-key", "", "WireGuard public key of this node")
		meshPort    = flag.Int("mesh-port", 51821, "Mesh control (PEX/DHT) TCP port")
		stunAddr    = flag.String("stun", "stun.l.google.com:19302", "STUN server address")
		seedPeers   = flag.String("seed", "", "Comma-separated seed peers (publickey@ip:port)")
		vpsAddr     = flag.String("vps", "", "VPS public address for WireGuard endpoint (ip:port), e.g. 175.178.118.76:51820")
		interfaceName = flag.String("interface", "wg0", "WireGuard interface name")
		wgEndpoint  = flag.String("wg-endpoint", "", "This node's WireGuard endpoint (ip:port) for DHT discovery. If empty, falls back to --vps value")
		relayAddr   = flag.String("relay", "", "VPS relay endpoint for fallback when P2P fails (ip:port), e.g. 175.178.118.76:51820")
		hubIntraIP = flag.String("hub-intra-ip", "", "VPS hub internal mesh IP for DHT fallback when public IP is blocked (e.g. 10.200.200.1)")
		hsTimeout   = flag.Duration("handshake-timeout", 2*time.Minute, "Handshake age threshold before removing P2P peer (0 = auto)")
		hsInterval  = flag.Duration("handshake-interval", 15*time.Second, "How often to check peer handshake status")
		restoreIntv = flag.Duration("restore-interval", 5*time.Minute, "How often to try restoring P2P peer from relay")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if *publicKey == "" {
		slog.Error("--public-key is required")
		os.Exit(1)
	}

	slog.Info("wg-meshd starting",
		"public_key", (*publicKey)[:16]+"...",
		"interface", *interfaceName,
		"mesh_port", *meshPort,
	)

	// 1. Initialize mesh state
	state := mesh.NewState(*publicKey)

	// 2. Connect to WireGuard via uapi (uses `wg` command on Linux)
	uapiClient := uapi.NewClient(*interfaceName)

	// 3. Initialize PEX protocol for peer exchange
	pexListen := fmt.Sprintf("0.0.0.0:%d", *meshPort)
	pexProto, err := pex.NewProtocol(
		*publicKey,
		pexListen,
		func() []pex.PeerEntry {
			peers := state.ConnectedPeers()
			entries := make([]pex.PeerEntry, 0, len(peers))
			for _, p := range peers {
				entries = append(entries, pex.PeerEntry{
					PublicKey: p.PublicKey,
					Endpoints: p.Endpoints,
				})
			}
			return entries
		},
		func(pk, endpoint string) error {
			slog.Info("pex connecting to peer", "pk", pk[:16]+"...", "ep", endpoint)
			return uapiClient.SetPeer(uapi.PeerConfig{
				PublicKey:  pk,
				Endpoint:   endpoint,
				AllowedIPs: "",
				KeepAlive:  25,
			})
		},
	)
	if err != nil {
		slog.Warn("pex protocol unavailable (non-fatal)", "error", err)
		pexProto = nil
	}

	// Resolve WG endpoint for DHT discovery
	localWgEp := *wgEndpoint

	// If --wg-endpoint not explicitly set, auto-discover public endpoint via STUN
	if *wgEndpoint == "" {
		// Get the local WireGuard listen port from wg show
		wgDump, err := uapiClient.ShowDump()
		var wgPort int
		if err == nil {
			lines := strings.Split(strings.TrimSpace(wgDump), "\n")
			if len(lines) > 0 {
				parts := strings.Split(lines[0], "	")
				if len(parts) >= 3 {
					wgPort, _ = strconv.Atoi(strings.TrimSpace(parts[2]))
				}
			}
		}
		if wgPort == 0 {
			wgPort = *meshPort // fallback: use mesh port as WG port hint
		}

		// Try STUN on the actual WG port via SO_REUSEPORT first.
		// This gives the exact CGNAT mapping (port and IP) when supported.
		var stunResult *nat.StunResult
		stunConn, err := reusableListenUDP(wgPort)
		if err == nil {
			stunResult, err = nat.DiscoverPublic(*stunAddr, stunConn)
			stunConn.Close()
		}
		if err != nil || stunResult == nil || stunResult.PublicIP == nil {
			// Fallback: STUN on a separate port to at least get the public IP.
			// The port will be the WG internal port (may differ from CGNAT mapping).
			slog.Debug("wg-port STUN unavailable, fallback to separate-port STUN", "error", err)
			stunConn2, err2 := net.ListenUDP("udp", &net.UDPAddr{Port: *meshPort + 10})
			if err2 == nil {
				stunResult, err2 = nat.DiscoverPublic(*stunAddr, stunConn2)
				stunConn2.Close()
				if err2 == nil && stunResult != nil && stunResult.PublicIP != nil {
					// We have the correct public IP; use WG internal port as endpoint.
					// NAT3's endpoint-independent mapping means the CGNAT port differs,
					// but the IP is correct — hub relay fallback handles the port mismatch.
					localWgEp = net.JoinHostPort(stunResult.PublicIP.String(), strconv.Itoa(wgPort))
					slog.Info("auto-discovered public IP from STUN",
						"endpoint", localWgEp,
						"nat_type", stunResult.NATType,
						"wg_port", wgPort,
					)
				}
			}
		} else {
			// REUSEPORT succeeded — we have the exact CGNAT mapping (IP + port)
			localWgEp = net.JoinHostPort(stunResult.PublicIP.String(), strconv.Itoa(stunResult.PublicPort))
			slog.Info("auto-discovered public WG endpoint from STUN",
				"endpoint", localWgEp,
				"nat_type", stunResult.NATType,
			)
		}

		if localWgEp == "" {
			slog.Warn("STUN discovery failed, falling back to --vps as DHT endpoint",
				"vps", *vpsAddr,
			)
			localWgEp = *vpsAddr
		}
	}
	if localWgEp == "" {
		localWgEp = *vpsAddr
	}

	// 4. Initialize DHT for bootstrap discovery (different port from PEX)
	dhtNode, err := dht.NewDHT(*publicKey, *meshPort+1, localWgEp)
	if err != nil {
		slog.Error("failed to create dht", "error", err)
		os.Exit(1)
	}

	// DHT 发现新 peer 时自动加到 WireGuard
	dhtNode.SetPeerCallback(func(c dht.Contact) {
		if c.PublicKey == "" {
			return
		}
		// 用 DHT 的 endpoint 配置 peer
		// AllowedIPs 留空：WireGuard 会保留已有的 VPS hub /24 路由
		// 用户可手动添加 /32 实现 P2P 直连
		if err := uapiClient.SetPeer(uapi.PeerConfig{
			PublicKey:  c.PublicKey,
			Endpoint:   c.Endpoint,
			AllowedIPs: "",
			KeepAlive:  25,
		}); err != nil {
			slog.Warn("failed to add dht peer to wireguard", "pk", c.PublicKey[:16], "error", err)
		} else {
			slog.Info("dht peer added to wireguard", "pk", c.PublicKey[:16], "ep", c.Endpoint)
		}
	})

	// 5. Parse seed peers (public DHT)
	var seeds []dht.Contact
	var vpsHubPubKey string
	if *seedPeers != "" {
		for _, s := range splitAndTrim(*seedPeers, ",") {
			parts := split(s, "@")
			if len(parts) == 2 {
				pk := stringsTrim(parts[0])
				ep := stringsTrim(parts[1])
				if pk != "" && ep != "" {
					if vpsHubPubKey == "" {
						vpsHubPubKey = pk
					}
					seeds = append(seeds, dht.Contact{
						ID:        dht.NodeID(pk),
						PublicKey: pk,
						Endpoint:  ep,
					})
					slog.Info("added seed peer", "pk", pk[:16]+"...", "ep", ep)
					// 立即加到 WireGuard：用 VPS 公开 WG 地址打洞
					wgEp := ep
					if *vpsAddr != "" {
						wgEp = *vpsAddr
					}
					if err := uapiClient.SetPeer(uapi.PeerConfig{
						PublicKey: pk,
						Endpoint:  wgEp,
						AllowedIPs: "10.200.200.0/24",
						KeepAlive: 25,
					}); err != nil {
						slog.Warn("failed to add seed to wireguard", "error", err)
					} else {
						slog.Info("seed peer added to wireguard", "pk", pk[:16]+"...", "ep", wgEp)
					}
				}
			}
		}
		if len(seeds) > 0 {
			dhtNode.Bootstrap(seeds)
		}
	}

	// 5b. DHT fallback via WG tunnel IP
	// If the public DHT seed is unreachable (CGNAT blocking TCP), retry via the
	// hub's internal mesh IP (10.200.200.1) through the existing WG tunnel.
	if *hubIntraIP != "" && vpsHubPubKey != "" {
		// Derive DHT port from the seed endpoint (same port, different IP)
		seedDhtPort := ""
		if len(seeds) > 0 {
			_, port, err := net.SplitHostPort(seeds[0].Endpoint)
			if err == nil {
				seedDhtPort = port
			}
		}
		if seedDhtPort != "" {
			intraEp := net.JoinHostPort(*hubIntraIP, seedDhtPort)
			slog.Info("adding DHT fallback via WG tunnel", "ep", intraEp)
			intraSeeds := []dht.Contact{{
				ID:        dht.NodeID(vpsHubPubKey),
				PublicKey: vpsHubPubKey,
				Endpoint:  intraEp,
			}}
			dhtNode.Bootstrap(intraSeeds)
		} else {
			slog.Warn("hub-intra-ip provided but could not determine DHT port from seed")
		}
	}

	// 6. Start protocols
	pexProto.Start()
	dhtNode.Start()

	slog.Info("wg-meshd running")

	// 8. Handshake monitor: remove P2P peers when stale, fallback to VPS hub relay
	if *relayAddr != "" && vpsHubPubKey != "" {
		slog.Info("handshake monitor started",
			"vps_hub_pk", vpsHubPubKey[:16]+"...",
			"timeout", *hsTimeout,
			"interval", *hsInterval,
		)
		relayCtx, relayCancel := context.WithCancel(context.Background())
		go runHandshakeMonitor(relayCtx, uapiClient, vpsHubPubKey, *hsTimeout, *hsInterval, *restoreIntv, state)
		defer relayCancel()
	} else {
		slog.Info("relay fallback disabled (no --relay or no seed)")
	}

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	slog.Info("shutting down")
	pexProto.Stop()
	dhtNode.Stop()
}

// runHandshakeMonitor periodically checks P2P peer handshake health.
// When a P2P peer's handshake is stale (>timeout), remove the /32 peer so
// traffic falls back to the VPS hub relay (10.200.200.0/24).
//
// Periodically try re-adding P2P peers. DHT/PEX will also re-discover them.
func runHandshakeMonitor(
	ctx context.Context,
	client *uapi.Client,
	vpsHubPubKey string, // VPS hub's public key — never remove this one
	timeout time.Duration,
	interval time.Duration,
	restoreInterval time.Duration,
	state *mesh.State,
) {
	// Track removed P2P peers for restoration
	type savedPeer struct {
		PublicKey  string
		Endpoint   string
		AllowedIPs string
		KeepAlive  int
		removedAt  time.Time
	}
	savedPeers := make(map[string]*savedPeer)

	check := func() {
		peers, err := client.ListPeers()
		if err != nil {
			slog.Warn("handshake monitor: list peers failed", "error", err)
			return
		}

		now := time.Now().Unix()

		// Phase 1: Check existing peers for stale handshakes
		for _, p := range peers {
			// Skip the VPS hub itself
			if p.PublicKey == vpsHubPubKey {
				continue
			}
			// Skip peers without a valid endpoint or handshake
			if p.Endpoint == "" || p.Endpoint == "(none)" || p.LatestHandshake == 0 {
				continue
			}
			// Skip peers not using a /32 (these are not P2P peers)
			if !strings.Contains(p.AllowedIPs, "/32") {
				continue
			}

			age := now - p.LatestHandshake
			// Check if already tracked as stale
			if _, exists := savedPeers[p.PublicKey]; exists {
				continue
			}

			if age > int64(timeout.Seconds()) {
				slog.Warn("P2P handshake stale, removing peer (traffic will use VPS hub relay)",
					"pk", p.PublicKey[:16],
					"age", age,
					"old_endpoint", p.Endpoint,
					"allowed_ips", p.AllowedIPs,
				)
				// Save before removing
				savedPeers[p.PublicKey] = &savedPeer{
					PublicKey:  p.PublicKey,
					Endpoint:   p.Endpoint,
					AllowedIPs: p.AllowedIPs,
					KeepAlive:  p.PersistentKeepalive,
					removedAt:  time.Now(),
				}
				if err := client.RemovePeer(p.PublicKey); err != nil {
					slog.Warn("failed to remove P2P peer", "error", err)
					delete(savedPeers, p.PublicKey)
					continue
				}
				state.UpsertPeer(p.PublicKey, func(ps *mesh.PeerState) {
					ps.IsConnected = false
				})
			}
		}

		// Phase 2: Try restoring removed P2P peers
		for pk, sp := range savedPeers {
			if time.Since(sp.removedAt) < restoreInterval/2 {
				continue
			}
			// Try adding the peer back
			slog.Info("attempting to restore P2P peer",
				"pk", pk[:16],
				"endpoint", sp.Endpoint,
			)
			if err := client.SetPeer(uapi.PeerConfig{
				PublicKey:  sp.PublicKey,
				Endpoint:   sp.Endpoint,
				AllowedIPs: sp.AllowedIPs,
				KeepAlive:  sp.KeepAlive,
			}); err != nil {
				slog.Warn("failed to restore P2P peer, will retry", "error", err)
				continue
			}
			// Don't remove from savedPeers yet — next cycle will check handshake
			sp.removedAt = time.Now()
		}

		// Phase 3: restored peers will be re-checked in next cycle's Phase 1.
		// If handshake is healthy, next cycle won't see them as stale and will
		// implicitly "forget" them.
		// We clean up savedPeers by checking if any tracked peer no longer exists
		// in the current list (it was re-added but then re-removed by DHT/PEX).
		type active struct{}
		activeKeys := make(map[string]active)
		for _, p := range peers {
			activeKeys[p.PublicKey] = active{}
		}
		for pk := range savedPeers {
			if _, exists := activeKeys[pk]; !exists {
				// Peer was removed by something else, clean up tracking
				slog.Debug("removed stale peer tracking (no longer in wg)", "pk", pk[:16])
				delete(savedPeers, pk)
			}
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run once immediately
	check()

	for {
		select {
		case <-ctx.Done():
			slog.Info("handshake monitor stopped")
			return
		case <-ticker.C:
			check()
		}
	}
}

func isExpired(t time.Time, d time.Duration) bool {
	return time.Since(t) >= d
}

// splitHost extracts host from "host:port" or returns the string as-is.
func splitHost(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func splitAndTrim(s, sep string) []string {
	var out []string
	for _, part := range split(s, sep) {
		trimmed := stringsTrim(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func split(s, sep string) []string {
	var result []string
	start := 0
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i = start - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func stringsTrim(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n') {
		end--
	}
	return s[start:end]
}

// reusableListenUDP binds a UDP port with SO_REUSEPORT to share it with
// another process (e.g., wireguard-go). On macOS, this allows multiple
// sockets to bind the same port when SO_REUSEADDR is also set.
// Used to STUN on the actual WireGuard port and discover the exact CGNAT mapping.
func reusableListenUDP(port int) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// SO_REUSEPORT = 0x0200 on macOS (SOL_SOCKET = 0xffff)
				syscall.SetsockoptInt(int(fd), 0xffff, 0x0200, 1)
			})
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
