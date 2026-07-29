// Package uapi manages WireGuard peer configuration.
// On Linux it uses the kernel module via the `wg` command (netlink).
// On macOS it uses the wireguard-go userspace daemon's Unix socket.
package uapi

import (
	"fmt"
	"os/exec"
	"strings"
)

// PeerConfig describes a WireGuard peer endpoint to configure.
type PeerConfig struct {
	PublicKey    string
	Endpoint     string // "ip:port"
	AllowedIPs   string // comma-separated CIDRs, e.g. "10.200.200.2/32"
	KeepAlive    int    // seconds, 0 = default
}

// Client manages WireGuard peer configuration on an interface.
type Client struct {
	iface string
}

func NewClient(interfaceName string) *Client {
	return &Client{iface: interfaceName}
}

// SetPeer adds or updates a peer using `wg set`.
func (c *Client) SetPeer(cfg PeerConfig) error {
	args := []string{"set", c.iface,
		"peer", cfg.PublicKey,
		"endpoint", cfg.Endpoint,
	}
	if cfg.AllowedIPs != "" {
		args = append(args, "allowed-ips", cfg.AllowedIPs)
	}
	if cfg.KeepAlive > 0 {
		args = append(args, "persistent-keepalive", fmt.Sprintf("%d", cfg.KeepAlive))
	}

	cmd := exec.Command("wg", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg set peer: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// RemovePeer removes a peer using `wg set <iface> peer <pk> remove`.
func (c *Client) RemovePeer(publicKey string) error {
	cmd := exec.Command("wg", "set", c.iface, "peer", publicKey, "remove")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg remove peer: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ShowDump returns all peers in dump format.
func (c *Client) ShowDump() (string, error) {
	cmd := exec.Command("wg", "show", c.iface, "dump")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("wg show dump: %w", err)
	}
	return string(out), nil
}
