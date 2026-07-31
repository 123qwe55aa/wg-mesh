#!/usr/bin/env python3
"""wg-mesh hub UDP echo server for NAT hole-punching tests.

Runs on the hub (public IP). nat3_test.py / nat4_test.py send PING-*
packets from behind a NAT; this server echoes them back so the client
can observe which source port the NAT used toward the hub, and whether
the mapping is stable (port hold) — the key EIM (NAT3) property.

Usage (on hub, e.g. 175.178.118.76):
    python3 echo_server.py [port]
"""
import socket, sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 52222

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", PORT))
print(f"[echo] listening 0.0.0.0:{PORT}")

while True:
    data, addr = s.recvfrom(2048)
    print(f"[echo] {addr[0]}:{addr[1]} -> {data!r}", flush=True)
    # Echo back with the observed source port annotated
    reply = f"ECHO:{addr[1]}:{data.decode(errors='replace')}".encode()
    s.sendto(reply, addr)
