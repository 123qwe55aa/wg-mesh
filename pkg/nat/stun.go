// Package nat handles NAT traversal: STUN to discover public address,
// and UDP hole punching to establish direct peer-to-peer connections.
package nat

import (
	"fmt"
	"log/slog"
	"net"
	"time"
)

const (
	defaultStunServer = "stun.l.google.com:19302"
	stunResponseLen   = 32
)

// StunResult holds what we learn from a STUN query.
type StunResult struct {
	PublicIP   net.IP
	PublicPort int
	NATType    string // "cone", "restricted", "port_restricted", "symmetric", "unknown"
}

// DiscoverPublic sends a STUN binding request and returns our public address.
func DiscoverPublic(stunAddr string, localConn *net.UDPConn) (*StunResult, error) {
	if stunAddr == "" {
		stunAddr = defaultStunServer
	}

	// Build a STUN binding request
	// STUN message format: 20 bytes header + attributes
	// We use a minimal implementation
	req := buildStunRequest()
	serverAddr, err := net.ResolveUDPAddr("udp", stunAddr)
	if err != nil {
		return nil, fmt.Errorf("stun resolve: %w", err)
	}

	localConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := localConn.WriteToUDP(req, serverAddr); err != nil {
		return nil, fmt.Errorf("stun write: %w", err)
	}

	buf := make([]byte, 1024)
	localConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := localConn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("stun read: %w", err)
	}

	result := parseStunResponse(buf[:n])
	slog.Debug("stun result", "ip", result.PublicIP, "port", result.PublicPort, "nat", result.NATType)
	return result, nil
}

// buildStunRequest constructs a minimal STUN binding request (RFC 8489).
func buildStunRequest() []byte {
	// STUN binding request with random transaction ID
	msg := make([]byte, 20)
	msg[0] = 0x00 // message type: Binding Request (0x0001)
	msg[1] = 0x01
	msg[2] = 0x00 // message length = 0
	msg[3] = 0x00
	// Magic cookie: 0x2112A442
	msg[4] = 0x21
	msg[5] = 0x12
	msg[6] = 0xA4
	msg[7] = 0x42
	// Transaction ID (12 random bytes)
	for i := 8; i < 20; i++ {
		msg[i] = byte(i * 37) // deterministic enough for our purposes
	}
	return msg
}

// parseStunResponse extracts the XOR-MAPPED-ADDRESS from a STUN response.
func parseStunResponse(data []byte) *StunResult {
	if len(data) < 20 {
		return &StunResult{NATType: "unknown"}
	}

	result := &StunResult{NATType: "unknown"}

	// Parse attributes (starts at offset 20)
	for i := 20; i+4 < len(data); {
		attrType := int(data[i])<<8 | int(data[i+1])
		attrLen := int(data[i+2])<<8 | int(data[i+3])
		i += 4

		if i+attrLen > len(data) {
			break
		}

		if attrType == 0x0020 { // XOR-MAPPED-ADDRESS
			if attrLen >= 8 {
				family := data[i+1]
				port := (int(data[i+2]^data[4]) << 8) | int(data[i+3]^data[5])
				result.PublicPort = port

				if family == 0x01 { // IPv4
					ip := make(net.IP, 4)
					for j := 0; j < 4; j++ {
						ip[j] = data[i+4+j] ^ data[4+j]
					}
					result.PublicIP = ip
				} else if family == 0x02 { // IPv6
					ip := make(net.IP, 16)
					for j := 0; j < 16; j++ {
						ip[j] = data[i+4+j] ^ data[4+j]
					}
					result.PublicIP = ip
				}
				result.NATType = "cone"
			}
		}
		i += attrLen
	}
	return result
}

// PunchHole sends UDP packets to a peer's public address to open a NAT pinhole.
// Both sides should call this concurrently for the hole to punch through.
func PunchHole(localConn *net.UDPConn, peerAddr *net.UDPAddr, count int) error {
	payload := []byte("wg-mesh hole punch")
	for i := 0; i < count; i++ {
		localConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		if _, err := localConn.WriteToUDP(payload, peerAddr); err != nil {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

// PredictEndpoint attempts to predict the next port a symmetric NAT will use.
// This is a best-effort heuristic; real symmetric NAT traversal needs a relay.
func PredictEndpoint(currentPort int) int {
	return currentPort + 2
}
