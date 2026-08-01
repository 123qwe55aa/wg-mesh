// Package uapi manages WireGuard peer configuration.
// On Linux it uses the kernel module via the `wg` command (netlink).
// On macOS it uses wireguard-go via `sudo -n wg`.
package uapi

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type PeerConfig struct {
	PublicKey  string
	Endpoint   string
	AllowedIPs string
	KeepAlive  int
}

// PeerInfo contains parsed information about a WireGuard peer from dump output.
type PeerInfo struct {
	PublicKey           string
	PresharedKey        string // "(none)" if not set
	Endpoint            string
	AllowedIPs          string
	LatestHandshake     int64 // unix timestamp, 0 if never
	TransferRx          int64
	TransferTx          int64
	PersistentKeepalive int
}

type Client struct {
	iface    string
	wgBinary string
}

func NewClient(interfaceName string) *Client {
	wgBin := "wg"
	if runtime.GOOS == "darwin" {
		// Find wg binary in common locations.
		// ~/.local/bin/wg first — it's the user-managed location with proper sudoers.
		home, _ := os.UserHomeDir()
		for _, p := range []string{
			home + "/.local/bin/wg",
			"/opt/homebrew/bin/wg",
			"/opt/homebrew/sbin/wg",
			"/usr/local/bin/wg",
		} {
			if _, err := os.Stat(p); err == nil {
				wgBin = "/usr/bin/sudo -n " + p
				break
			}
		}
		// Fallback to just "wg" in PATH
		if wgBin == "wg" {
			wgBin = "/usr/bin/sudo -n wg"
		}
	}
	return &Client{iface: interfaceName, wgBinary: wgBin}
}

func (c *Client) buildArgs(cfg PeerConfig) []string {
	parts := strings.Fields(c.wgBinary)
	args := append(parts[1:], "set", c.iface,
		"peer", cfg.PublicKey,
		"endpoint", cfg.Endpoint,
	)
	if cfg.AllowedIPs != "" {
		args = append(args, "allowed-ips", cfg.AllowedIPs)
	}
	if cfg.KeepAlive > 0 {
		args = append(args, "persistent-keepalive", fmt.Sprintf("%d", cfg.KeepAlive))
	}
	return args
}

func (c *Client) SetPeer(cfg PeerConfig) error {
	parts := strings.Fields(c.wgBinary)
	args := c.buildArgs(cfg)
	cmd := exec.Command(parts[0], args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg set peer: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (c *Client) RemovePeer(publicKey string) error {
	parts := strings.Fields(c.wgBinary)
	args := append(parts[1:], "set", c.iface, "peer", publicKey, "remove")
	cmd := exec.Command(parts[0], args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg remove peer: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (c *Client) ShowDump() (string, error) {
	parts := strings.Fields(c.wgBinary)
	args := append(parts[1:], "show", c.iface, "dump")
	cmd := exec.Command(parts[0], args...)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("wg show dump: %w", err)
	}
	return string(out), nil
}

// ListPeers returns all peers with their current status from wg show dump.
func (c *Client) ListPeers() ([]PeerInfo, error) {
	dump, err := c.ShowDump()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(dump), "\n")
	if len(lines) < 2 {
		// Only the interface line, no peers
		return nil, nil
	}
	var peers []PeerInfo
	for _, line := range lines[1:] {
		parts := strings.Split(line, "	")
		if len(parts) < 8 {
			continue
		}
		hs, _ := strconv.ParseInt(parts[4], 10, 64)
		rx, _ := strconv.ParseInt(parts[5], 10, 64)
		tx, _ := strconv.ParseInt(parts[6], 10, 64)
		ka, _ := strconv.Atoi(parts[7])
		peers = append(peers, PeerInfo{
			PublicKey:           parts[0],
			PresharedKey:        parts[1],
			Endpoint:            parts[2],
			AllowedIPs:          parts[3],
			LatestHandshake:     hs,
			TransferRx:          rx,
			TransferTx:          tx,
			PersistentKeepalive: ka,
		})
	}
	return peers, nil
}

// SetEndpoint changes only the endpoint for an existing peer.
func (c *Client) SetEndpoint(publicKey, endpoint string) error {
	parts := strings.Fields(c.wgBinary)
	args := append(parts[1:], "set", c.iface, "peer", publicKey, "endpoint", endpoint)
	cmd := exec.Command(parts[0], args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg set endpoint: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// SetEndpointFast updates a peer through WireGuard's UAPI socket when it is
// available, avoiding one process spawn per candidate during a port scan.
// It falls back to the normal wg CLI on platforms without an accessible UAPI.
func (c *Client) SetEndpointFast(publicKey, endpoint string) error {
	paths := []string{
		"/var/run/wireguard/" + c.iface + ".sock",
		"/run/wireguard/" + c.iface + ".sock",
	}
	for _, path := range paths {
		conn, err := net.DialTimeout("unix", path, 500*time.Millisecond)
		if err != nil {
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		// WireGuard UAPI expects the peer public key as 64 hex characters;
		// wg-mesh stores keys in base64 for the `wg` CLI.
		keyBytes, decodeErr := base64.StdEncoding.DecodeString(publicKey)
		if decodeErr != nil || len(keyBytes) != 32 {
			_ = conn.Close()
			return c.SetEndpoint(publicKey, endpoint)
		}
		uapiKey := hex.EncodeToString(keyBytes)
		_, err = fmt.Fprintf(conn, "set=1\npublic_key=%s\nendpoint=%s\n\n", uapiKey, endpoint)
		if err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			line, readErr := bufio.NewReader(conn).ReadString('\n')
			if readErr == nil && strings.TrimSpace(line) == "errno=0" {
				_ = conn.Close()
				return nil
			}
			err = fmt.Errorf("uapi response: %s", strings.TrimSpace(line))
		}
		_ = conn.Close()
		if err != nil {
			break
		}
	}
	return c.SetEndpoint(publicKey, endpoint)
}
