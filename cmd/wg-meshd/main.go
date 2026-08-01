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
		publicKey       = flag.String("public-key", "", "WireGuard public key of this node")
		meshPort        = flag.Int("mesh-port", 51821, "Mesh control (PEX/DHT) TCP port")
		stunAddr        = flag.String("stun", "stun.miwifi.com:3478", "STUN server address")
		seedPeers       = flag.String("seed", "", "Comma-separated seed peers (publickey@ip:port)")
		vpsAddr         = flag.String("vps", "", "VPS public address for WireGuard endpoint (ip:port), e.g. 175.178.118.76:51820")
		interfaceName   = flag.String("interface", "wg0", "WireGuard interface name")
		wgEndpoint      = flag.String("wg-endpoint", "", "This node's WireGuard endpoint (ip:port) for DHT discovery. If empty, falls back to --vps value")
		relayAddr       = flag.String("relay", "", "VPS relay endpoint for fallback when P2P fails (ip:port), e.g. 175.178.118.76:51820")
		hubIntraIP      = flag.String("hub-intra-ip", "", "VPS hub internal mesh IP for DHT fallback when public IP is blocked (e.g. 10.200.200.1)")
		hsTimeout       = flag.Duration("handshake-timeout", 2*time.Minute, "Handshake age threshold before removing P2P peer (0 = auto)")
		hsInterval      = flag.Duration("handshake-interval", 15*time.Second, "How often to check peer handshake status")
		restoreIntv     = flag.Duration("restore-interval", 5*time.Minute, "How often to try restoring P2P peer from relay")
		blindScan       = flag.Bool("blind-scan", true, "Scan candidate UDP ports after a stale P2P handshake")
		blindScanPorts  = flag.Int("blind-scan-ports", 65535, "Maximum candidate ports to try (1-65535)")
		blindScanRate   = flag.Int("blind-scan-rate", 230, "Target blind-scan endpoint updates per second")
		blindScanBudget = flag.Duration("blind-scan-budget", 330*time.Second, "Maximum total time for one blind scan")
		syncPunch       = flag.Bool("sync-punch", false, "Enable Hub-coordinated synchronized punching (experimental)")
		syncPunchWindow = flag.Duration("sync-punch-window", 500*time.Millisecond, "Synchronized punch window")
		syncPunchLead   = flag.Duration("sync-punch-lead", 750*time.Millisecond, "Lead time before synchronized punch starts")
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
	if localWgEp == "" {
		localWgEp = *vpsAddr
	}

	// Auto-discover public endpoint via STUN (only when --wg-endpoint not explicitly set)
	var publicWgEp string
	var stunNATType string
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
			slog.Warn("STUN failed — DHT will register via TCP address fallback",
				"wg_port", wgPort,
				"error", err,
			)
			stunConn2, err2 := net.ListenUDP("udp", &net.UDPAddr{Port: *meshPort + 10})
			if err2 == nil {
				stunResult, err2 = nat.DiscoverPublic(*stunAddr, stunConn2)
				stunConn2.Close()
				if err2 == nil && stunResult != nil && stunResult.PublicIP != nil {
					publicWgEp = net.JoinHostPort(stunResult.PublicIP.String(), strconv.Itoa(wgPort))
					stunNATType = stunResult.NATType
					slog.Info("auto-discovered public IP from STUN",
						"public_ep", publicWgEp,
						"lan_ep", localWgEp,
						"nat_type", stunNATType,
						"wg_port", wgPort,
					)
				}
			}
		} else {
			// REUSEPORT succeeded — we have the exact CGNAT mapping (IP + port)
			publicWgEp = net.JoinHostPort(stunResult.PublicIP.String(), strconv.Itoa(stunResult.PublicPort))
			stunNATType = stunResult.NATType
			slog.Info("auto-discovered public WG endpoint from STUN",
				"public_ep", publicWgEp,
				"lan_ep", localWgEp,
				"nat_type", stunNATType,
			)
		}
		// If STUN failed entirely and --wg-endpoint was not explicitly set,
		// clear localWgEp so DHT sends no WgEndpoint. Hub will use the TCP
		// connection's source address as fallback in handleFindNode.
		if *wgEndpoint == "" && publicWgEp == "" {
			localWgEp = ""
		}
	}

	// 4. Initialize DHT for bootstrap discovery (different port from PEX)
	dhtNode, err := dht.NewDHT(*publicKey, *meshPort+1, localWgEp)
	if err != nil {
		slog.Error("failed to create dht", "error", err)
		os.Exit(1)
	}
	// On the Linux hub, publish the endpoint actually observed by WireGuard.
	// This intentionally overrides STUN/self-reported values: the hub sees the
	// real NAT source port of Toby's WG packets.
	if *interfaceName == "wg0" {
		dhtNode.SetObservedEndpoint(func(pk string) string {
			peers, err := uapiClient.ListPeers()
			if err != nil {
				return ""
			}
			for _, p := range peers {
				if p.PublicKey == pk && p.Endpoint != "" && p.Endpoint != "(none)" {
					return p.Endpoint
				}
			}
			return ""
		})
	}

	// Register public endpoint for NAT traversal (only when STUN-discovered and differs from LAN)
	if publicWgEp != "" && publicWgEp != localWgEp {
		dhtNode.SetPublicEndpoint(publicWgEp)
		slog.Info("dht registered dual endpoints",
			"lan", localWgEp,
			"public", publicWgEp,
			"nat_type", stunNATType,
		)
	}

	// DHT 发现新 peer 时自动加到 WireGuard
	dhtNode.SetPeerCallback(func(c dht.Contact) {
		if c.PublicKey == "" {
			return
		}
		// 优先用 PublicEndpoint（跨网可达），fallback 到 LAN endpoint
		// WG roaming 会自动切换到更优路径
		wgEp := c.Endpoint
		if c.PublicEndpoint != "" {
			wgEp = c.PublicEndpoint
		}
		if err := uapiClient.SetPeer(uapi.PeerConfig{
			PublicKey:  c.PublicKey,
			Endpoint:   wgEp,
			AllowedIPs: "",
			KeepAlive:  25,
		}); err != nil {
			slog.Warn("failed to add dht peer to wireguard", "pk", c.PublicKey[:16], "error", err)
		} else {
			slog.Info("dht peer added to wireguard",
				"pk", c.PublicKey[:16],
				"ep", wgEp,
				"lan_ep", c.Endpoint,
				"public_ep", c.PublicEndpoint,
			)
			if c.ControlEndpoint != "" {
				if err := dhtNode.OpenControl(c); err != nil {
					slog.Debug("dht control channel unavailable", "pk", c.PublicKey[:16], "error", err)
				}
			}
			// Report connection state to hub for cross-network visibility
			dhtNode.SendState(c.PublicKey, "connected", wgEp)
		}
	})

	// Synchronized punch executor. PunchPorts contains complete host:port
	// candidates; the relay peer is never modified by this callback.
	dhtNode.SetPunchPlanCallback(func(plan dht.DhtMessage) {
		if plan.TargetPublicKey == "" || plan.TargetPublicKey == *publicKey || len(plan.PunchPorts) == 0 {
			return
		}
		go runPunchPlan(plan, uapiClient)
	})
	if *syncPunch && *interfaceName == "wg0" {
		go scheduleHubPunch(dhtNode, *publicKey, *syncPunchWindow, *syncPunchLead)
	}

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
						PublicKey:  pk,
						Endpoint:   wgEp,
						AllowedIPs: "10.200.200.0/24",
						KeepAlive:  25,
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

	// Signal channel for graceful shutdown (used by refresh and monitor goroutines)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 8. Periodic DHT refresh + STUN re-discovery.
	// Re-discover public endpoint to detect network changes (CGNAT IP change,
	// network switch, etc.). The updated publicEndpoint is included in subsequent
	// findNode requests so the DHT registration stays current.
	// Without this, a node that changes networks would keep announcing a stale
	// endpoint, breaking P2P connectivity for all peers.
	go func() {
		refreshTicker := time.NewTicker(5 * time.Minute)
		defer refreshTicker.Stop()
		for {
			select {
			case <-refreshTicker.C:
				if *wgEndpoint == "" {
					newPublicWgEp, newNATType := discoverPublicEndpoint(*stunAddr, uapiClient, *meshPort)
					if newPublicWgEp != "" && newPublicWgEp != publicWgEp {
						slog.Info("public endpoint changed, updating DHT registration",
							"old", publicWgEp,
							"new", newPublicWgEp,
							"nat_type", newNATType,
						)
						publicWgEp = newPublicWgEp
						stunNATType = newNATType
						dhtNode.SetPublicEndpoint(publicWgEp)
					}
				}
				slog.Debug("dht refresh cycle starting")
				dhtNode.Refresh()
			case <-sigCh:
				return
			}
		}
	}()

	// 9. Handshake monitor: remove P2P peers when stale, fallback to VPS hub relay
	if *relayAddr != "" && vpsHubPubKey != "" {
		slog.Info("handshake monitor started",
			"vps_hub_pk", vpsHubPubKey[:16]+"...",
			"timeout", *hsTimeout,
			"interval", *hsInterval,
		)
		relayCtx, relayCancel := context.WithCancel(context.Background())
		go runHandshakeMonitor(relayCtx, uapiClient, vpsHubPubKey, *hsTimeout, *hsInterval, *restoreIntv, *blindScan, *blindScanPorts, *blindScanRate, *blindScanBudget, state)
		defer relayCancel()
	} else {
		slog.Info("relay fallback disabled (no --relay or no seed)")
	}

	// Wait for signal
	<-sigCh

	slog.Info("shutting down")
	pexProto.Stop()
	dhtNode.Stop()
}

func runPunchPlan(plan dht.DhtMessage, client *uapi.Client) {
	window := time.Duration(plan.PunchWindowMs) * time.Millisecond
	if window <= 0 {
		window = 500 * time.Millisecond
	}
	// Allow control-plane scheduling jitter, but never start early.
	for {
		remaining := time.Until(time.UnixMilli(plan.PunchStartUnix))
		if remaining <= 0 {
			break
		}
		if remaining > 50*time.Millisecond {
			time.Sleep(remaining - 25*time.Millisecond)
		} else {
			time.Sleep(remaining)
		}
	}
	peers, err := client.ListPeers()
	if err != nil {
		return
	}
	var baselineRx int64
	for _, p := range peers {
		if p.PublicKey == plan.TargetPublicKey {
			baselineRx = p.TransferRx
			break
		}
	}
	startedAt := time.Now().Unix()
	for _, endpoint := range plan.PunchPorts {
		if err := client.SetEndpointFast(plan.TargetPublicKey, endpoint); err != nil {
			continue
		}
		deadline := time.Now().Add(window)
		for time.Now().Before(deadline) {
			peers, err = client.ListPeers()
			if err == nil {
				for _, p := range peers {
					if p.PublicKey == plan.TargetPublicKey && p.Endpoint == endpoint &&
						p.LatestHandshake >= startedAt && p.TransferRx > baselineRx {
						slog.Info("synchronized punch found direct endpoint", "punch_id", plan.PunchID, "endpoint", endpoint)
						return
					}
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	slog.Info("synchronized punch window completed", "punch_id", plan.PunchID, "candidates", len(plan.PunchPorts))
}

func scheduleHubPunch(node *dht.DHT, selfPK string, window, lead time.Duration) {
	if window <= 0 {
		window = 500 * time.Millisecond
	}
	if lead <= 0 {
		lead = 750 * time.Millisecond
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		peers := node.KnownPeers()
		for i := 0; i < len(peers); i++ {
			a := peers[i]
			if a.PublicKey == "" || a.PublicKey == selfPK || a.PublicEndpoint == "" {
				continue
			}
			for j := i + 1; j < len(peers); j++ {
				b := peers[j]
				if b.PublicKey == "" || b.PublicKey == selfPK || b.PublicEndpoint == "" {
					continue
				}
				start := time.Now().Add(lead)
				id := fmt.Sprintf("%d-%s-%s", start.UnixMilli(), a.PublicKey[:8], b.PublicKey[:8])
				portsA := []string{b.PublicEndpoint}
				portsB := []string{a.PublicEndpoint}
				errA := node.SendPunchPlan(a, b.PublicKey, b.PublicEndpoint, id, start, window, portsA)
				errB := node.SendPunchPlan(b, a.PublicKey, a.PublicEndpoint, id, start, window, portsB)
				if errA != nil || errB != nil {
					slog.Warn("sync punch pair failed", "a", a.PublicKey[:16], "b", b.PublicKey[:16], "a_error", errA, "b_error", errB)
				} else {
					slog.Info("sync punch pair sent", "a", a.PublicKey[:16], "b", b.PublicKey[:16], "start", start, "window", window)
				}
			}
		}
	}
}

func normalizedAllowedIPs(allowed string) string {
	if allowed == "" || allowed == "(none)" {
		return ""
	}
	return allowed
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
	blindScan bool,
	blindScanPorts int,
	blindScanRate int,
	blindScanBudget time.Duration,
	state *mesh.State,
) {
	// Track P2P peers whose /32 route was cleared for restoration
	type savedPeer struct {
		PublicKey  string
		Endpoint   string
		AllowedIPs string
		KeepAlive  int
		BaselineRx int64
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
			// Skip peers without a valid endpoint. A zero handshake is still
			// recoverable: it means this endpoint has never succeeded, so send it
			// through the blind scanner instead of waiting forever.
			if p.Endpoint == "" || p.Endpoint == "(none)" {
				continue
			}
			// A discovered P2P peer may temporarily have no AllowedIPs: DHT/PEX
			// historically installed peers with an empty routing set. It can still
			// be probed via WireGuard keepalive, so do not exclude it from endpoint
			// recovery solely for that reason. Relay (/24) peers are excluded below.
			if strings.Contains(p.AllowedIPs, "/24") {
				continue
			}

			age := now - p.LatestHandshake
			// Check if already tracked as stale
			if _, exists := savedPeers[p.PublicKey]; exists {
				continue
			}

			if age > int64(timeout.Seconds()) {
				slog.Warn("P2P handshake stale, clearing /32 route (traffic will use VPS hub relay)",
					"pk", p.PublicKey[:16],
					"age", age,
					"old_endpoint", p.Endpoint,
				)
				normalized := normalizedAllowedIPs(p.AllowedIPs)
				if normalized != "" {
					if err := client.SetPeer(uapi.PeerConfig{
						PublicKey:  p.PublicKey,
						Endpoint:   p.Endpoint,
						AllowedIPs: "",
						KeepAlive:  p.PersistentKeepalive,
					}); err != nil {
						slog.Warn("failed to clear P2P /32 route", "error", err)
					}
				}
				savedPeers[p.PublicKey] = &savedPeer{
					PublicKey:  p.PublicKey,
					Endpoint:   p.Endpoint,
					AllowedIPs: normalized,
					KeepAlive:  p.PersistentKeepalive,
					BaselineRx: p.TransferRx,
					removedAt:  time.Now(),
				}
				state.UpsertPeer(p.PublicKey, func(ps *mesh.PeerState) {
					ps.IsConnected = false
				})
			}
		}

		// Phase 2: Try restoring P2P peers whose /32 was cleared
		for pk, sp := range savedPeers {
			if time.Since(sp.removedAt) < restoreInterval/2 {
				continue
			}
			// Try a bounded blind scan before restoring the old endpoint. A successful
			// WireGuard handshake is the only acceptance signal; UDP replies alone
			// are not sufficient.
			if blindScan {
				if endpoint, ok := blindScanEndpoint(ctx, client, sp.PublicKey, sp.Endpoint, sp.AllowedIPs, sp.KeepAlive, sp.BaselineRx, blindScanPorts, blindScanRate, blindScanBudget); ok {
					slog.Info("blind scan found direct endpoint", "pk", pk[:16], "endpoint", endpoint)
					sp.Endpoint = endpoint
					delete(savedPeers, pk)
					state.UpsertPeer(pk, func(ps *mesh.PeerState) { ps.IsConnected = true })
					continue
				}
			}

			// Fall back to restoring the previously known endpoint.
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

		// Phase 3: keep savedPeers until a scan succeeds. DHT/PEX may remove
		// the peer while it is being recovered; deleting the tracking entry just
		// because it is absent from this snapshot would prevent blind scanning.
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

// blindScanEndpoint tries candidate UDP ports around the last known endpoint.
// It uses WireGuard's handshake timestamp as the success signal, not arbitrary
// UDP traffic. The scan is deliberately bounded and cancellable.
func blindScanEndpoint(ctx context.Context, client *uapi.Client, publicKey, oldEndpoint, allowedIPs string, keepAlive int, baselineRx int64, count, rate int, budget time.Duration) (string, bool) {
	host, portText, err := net.SplitHostPort(oldEndpoint)
	if err != nil {
		return "", false
	}
	center, err := strconv.Atoi(portText)
	if err != nil || center < 1 || center > 65535 || count <= 0 {
		return "", false
	}
	if count > 65535 {
		count = 65535
	}
	if rate <= 0 {
		rate = 200
	}
	if budget <= 0 {
		budget = 330 * time.Second
	}
	scanStarted := time.Now()
	startedAt := scanStarted.Unix()
	deadline := scanStarted.Add(budget)
	// Priority tiers: historical neighborhood, predicted neighborhood,
	// predicted region, then every remaining port. A bitmap prevents repeats.
	ports := prioritizedPorts(center, count)
	slog.Info("starting blind endpoint scan", "peer", publicKey[:16], "host", host, "candidates", len(ports), "rate", rate, "budget", budget)

	for i, p := range ports {
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return "", false
		default:
		}
		endpoint := net.JoinHostPort(host, strconv.Itoa(p))
		var setErr error
		if i == 0 {
			// The stale peer was removed before scanning, so create it with its
			// routing attributes on the first candidate.
			setErr = client.SetPeer(uapi.PeerConfig{
				PublicKey:  publicKey,
				Endpoint:   endpoint,
				AllowedIPs: allowedIPs,
				KeepAlive:  keepAlive,
			})
		} else {
			setErr = client.SetEndpointFast(publicKey, endpoint)
		}
		if setErr != nil {
			continue
		}
		// Avoid invoking wg show for every candidate, while still stopping soon
		// after a real handshake arrives.
		if i == 0 || i%16 == 0 {
			peers, listErr := client.ListPeers()
			if listErr == nil {
				for _, peer := range peers {
					if peer.PublicKey == publicKey &&
						peer.Endpoint == endpoint &&
						peer.LatestHandshake >= startedAt &&
						peer.TransferRx > baselineRx {
						return endpoint, true
					}
				}
			}
		}
		// Monotonic pacing; elapsed work is accounted for automatically.
		target := time.Duration(i+1) * time.Second / time.Duration(rate)
		wait := target - time.Since(scanStarted)
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", false
		case <-timer.C:
		}
	}
	return "", false
}

func prioritizedPorts(center, count int) []int {
	if count <= 0 || count > 65535 {
		count = 65535
	}
	seen := make([]bool, 65536)
	out := make([]int, 0, count)
	add := func(p int) {
		if p >= 1 && p <= 65535 && !seen[p] && len(out) < count {
			seen[p] = true
			out = append(out, p)
		}
	}
	for d := 0; d <= 512; d++ {
		add(center - d)
		if d != 0 {
			add(center + d)
		}
	}
	for d := 513; d <= 4096; d++ {
		add(center - d)
		add(center + d)
	}
	for p := center - 4096; p <= center+4096; p++ {
		add(p)
	}
	for p := 1; p <= 65535; p++ {
		add(p)
	}
	return out
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

// discoverPublicEndpoint performs STUN discovery to find this node's public
// WireGuard endpoint. Returns the public endpoint string and NAT type.
// Returns ("", "") if discovery fails or no WG port is available.
// This is called both at startup and periodically to detect network changes.
func discoverPublicEndpoint(stunAddr string, client *uapi.Client, meshPort int) (publicWgEp string, natType string) {
	wgDump, err := client.ShowDump()
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
		wgPort = meshPort
	}

	var stunResult *nat.StunResult
	stunConn, err := reusableListenUDP(wgPort)
	if err == nil {
		stunResult, err = nat.DiscoverPublic(stunAddr, stunConn)
		stunConn.Close()
	}
	if err != nil || stunResult == nil || stunResult.PublicIP == nil {
		stunConn2, err2 := net.ListenUDP("udp", &net.UDPAddr{Port: meshPort + 10})
		if err2 == nil {
			stunResult, err2 = nat.DiscoverPublic(stunAddr, stunConn2)
			stunConn2.Close()
			if err2 == nil && stunResult != nil && stunResult.PublicIP != nil {
				publicWgEp = net.JoinHostPort(stunResult.PublicIP.String(), strconv.Itoa(wgPort))
				natType = stunResult.NATType
				slog.Info("discover: public IP from STUN",
					"public_ep", publicWgEp,
					"nat_type", natType,
					"wg_port", wgPort,
				)
			}
		}
	} else {
		publicWgEp = net.JoinHostPort(stunResult.PublicIP.String(), strconv.Itoa(stunResult.PublicPort))
		natType = stunResult.NATType
		slog.Info("discover: public WG endpoint from STUN",
			"public_ep", publicWgEp,
			"nat_type", natType,
		)
	}
	return
}
