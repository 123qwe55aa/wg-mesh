// Package uapi manages WireGuard peer configuration.
// On Linux it uses the kernel module via the `wg` command (netlink).
// On macOS it uses wireguard-go via `sudo -n wg`.
package uapi

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

type PeerConfig struct {
	PublicKey  string
	Endpoint   string
	AllowedIPs string
	KeepAlive  int
}

type Client struct {
	iface    string
	wgBinary string
}

func NewClient(interfaceName string) *Client {
	wgBin := "wg"
	if runtime.GOOS == "darwin" {
		wgBin = "/usr/bin/sudo -n /opt/homebrew/bin/wg"
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
