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
//	                         PEX UDP           DHT UDP          STUN UDP
//	                     (peer exchange)   (bootstrap)      (NAT traversal)
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/123qwe55aa/wg-mesh/pkg/dht"
	"github.com/123qwe55aa/wg-mesh/pkg/mesh"
	"github.com/123qwe55aa/wg-mesh/pkg/nat"
	"github.com/123qwe55aa/wg-mesh/pkg/pex"
	"github.com/123qwe55aa/wg-mesh/pkg/uapi"
)

func main() {
	var (
		publicKey   = flag.String("public-key", "", "WireGuard public key of this node")
		meshPort    = flag.Int("mesh-port", 51821, "Mesh control (PEX/DHT) UDP port")
		stunAddr    = flag.String("stun", "stun.l.google.com:19302", "STUN server address")
		seedPeers   = flag.String("seed", "", "Comma-separated seed peers (publickey@ip:port)")
		vpsAddr     = flag.String("vps", "", "VPS public address for WireGuard endpoint (ip:port), e.g. 175.178.118.76:51820")
		interfaceName = flag.String("interface", "wg0", "WireGuard interface name")
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

	// 4. Initialize DHT for bootstrap discovery (different port from PEX)
	dhtNode, err := dht.NewDHT(*publicKey, *meshPort+1)
	if err != nil {
		slog.Error("failed to create dht", "error", err)
		os.Exit(1)
	}

	// DHT 发现新 peer 时自动加到 WireGuard
	dhtNode.SetPeerCallback(func(c dht.Contact) {
		if c.PublicKey == "" {
			return
		}
		// 用 DHT 的 endpoint 配置 peer，Mac 主动握手
		if err := uapiClient.SetPeer(uapi.PeerConfig{
			PublicKey:  c.PublicKey,
			Endpoint:   c.Endpoint,
			AllowedIPs: "10.200.200.0/24",
			KeepAlive:  25,
		}); err != nil {
			slog.Warn("failed to add dht peer to wireguard", "pk", c.PublicKey[:16], "error", err)
		} else {
			slog.Info("dht peer added to wireguard", "pk", c.PublicKey[:16], "ep", c.Endpoint)
		}
	})

	// 5. Parse seed peers
	if *seedPeers != "" {
		var seeds []dht.Contact
		for _, s := range splitAndTrim(*seedPeers, ",") {
			parts := split(s, "@")
			if len(parts) == 2 {
				pk := stringsTrim(parts[0])
				ep := stringsTrim(parts[1])
				if pk != "" && ep != "" {
					seeds = append(seeds, dht.Contact{
						ID:       dht.NodeID(pk),
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

	// 6. Start protocols
	pexProto.Start()
	dhtNode.Start()

	// 7. STUN to discover public address
	stunConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: *meshPort + 10})
	if err == nil {
		result, err := nat.DiscoverPublic(*stunAddr, stunConn)
		if err == nil {
			slog.Info("public address",
				"ip", result.PublicIP,
				"port", result.PublicPort,
				"nat_type", result.NATType,
			)
		}
		stunConn.Close()
	}

	slog.Info("wg-meshd running")

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	slog.Info("shutting down")
	pexProto.Stop()
	dhtNode.Stop()
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
