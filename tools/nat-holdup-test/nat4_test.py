#!/usr/bin/env python3
"""wg-mesh NAT4 (symmetric) verification — port allocation behavior.

Run this on a network suspected to be NAT4. Uses ONE local socket to
probe MULTIPLE distinct STUN destinations; a symmetric NAT assigns a
different external port per destination (Address/Port-Dependent
Mapping), while EIM (NAT3) reuses one port for all destinations.

Also verifies sequential-allocation detection: if the external ports
form a stable arithmetic sequence, sequential port prediction is
feasible (see pkg/nat/predict.go). If they are unrelated, the NAT
randomizes allocation — prediction impossible, blind probing needed.

Usage:
    python3 nat4_test.py

Environment variables (optional):
    STUN1/STUN2/STUN3  — probe targets (default: miwifi/google/cloudflare)
"""
import os, socket, struct, time

STUN_TARGETS = [
    ("111.206.174.2", 3478),        # stun.miwifi.com
    ("74.125.250.129", 19302),      # stun.l.google.com
    ("162.159.207.0", 3478),        # stun.cloudflare.com
    ("74.125.250.130", 19302),      # stun1.l.google.com (same /24, diff IP)
]

def stun_request(conn, server, seq):
    msg = bytearray(20)
    msg[0], msg[1] = 0x00, 0x01
    msg[4:8] = bytes([0x21, 0x12, 0xA4, 0x42])
    for i in range(12):
        msg[8+i] = (seq + i) & 0xff
    conn.sendto(bytes(msg), server)

def parse_stun(data):
    if len(data) < 20:
        return None
    magic = bytes([0x21, 0x12, 0xA4, 0x42])
    pos = 20
    while pos + 4 <= len(data):
        atype, alen = struct.unpack(">HH", data[pos:pos+4])
        if atype in (0x0001, 0x0020) and pos+12 <= len(data):
            family = data[pos+5]
            port = struct.unpack(">H", data[pos+6:pos+8])[0]
            ipb = data[pos+8:pos+12]
            if atype == 0x0020:
                port ^= 0x2112
                ipb = bytes(b ^ m for b, m in zip(ipb, magic))
            return socket.inet_ntoa(ipb), port
        pos += 4 + alen + (alen % 2)
    return None

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 0))
local_port = s.getsockname()[1]
print(f"[local] bound 0.0.0.0:{local_port}")

# 3 rounds: each round probes all targets with the SAME socket
results = {}  # target -> list of external ports seen across rounds
for round_no in range(3):
    for seq, target in enumerate(STUN_TARGETS):
        stun_request(s, target, round_no * 100 + seq)
        s.settimeout(3)
        try:
            data, _ = s.recvfrom(1024)
            r = parse_stun(data)
            if r:
                results.setdefault(target, []).append(r[1])
                print(f"[round{round_no}] {target[0]}:{target[1]} -> external {r[0]}:{r[1]}")
        except socket.timeout:
            print(f"[round{round_no}] {target[0]}:{target[1]} -> timeout")
    time.sleep(0.5)

print("\n=== analysis ===")
# Per-target stability (each destination's mapping must be stable)
all_stable = True
for target, ports in results.items():
    stable = len(set(ports)) == 1
    all_stable &= stable
    print(f"[target] {target[0]}:{target[1]} ports={ports} stable={stable}")

# Cross-target: EIM reuses one port; ADM/APDM differs per target
ports_by_target = {t: p[0] for t, p in results.items() if p}
distinct = set(ports_by_target.values())
print(f"[mapping] distinct external ports across targets: {sorted(distinct)}")
if len(distinct) == 1:
    print("[mapping] -> EIM (Endpoint-Independent Mapping) = NAT1-3 family")
else:
    print(f"[mapping] -> ADM/APDM (per-destination ports) = NAT4 (symmetric)")

# Sequential prediction check
seq = sorted(distinct)
if len(seq) >= 2:
    deltas = [seq[i+1] - seq[i] for i in range(len(seq)-1)]
    print(f"[predict] sorted external ports: {seq}, deltas: {deltas}")
    if len(set(deltas)) == 1 and deltas[0] != 0:
        print(f"[predict] stable delta {deltas[0]} -> SEQUENTIAL, port prediction FEASIBLE")
    else:
        print("[predict] no stable delta -> allocation RANDOMIZED, prediction NOT feasible (blind probe / relay only)")
s.close()
