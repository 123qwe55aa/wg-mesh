#!/usr/bin/env python3
"""wg-mesh NAT3 打洞实验:
1. 固定本地端口,多次 STUN → 验证 EIM 映射稳定(端口保持)
2. 同一 socket 打 hub → hub 侧观察源端口是否 = STUN 端口
3. hub echo 回包 → 验证双向打通
"""
import socket, struct, time, sys

STUN = ("111.206.174.2", 3478)   # stun.miwifi.com,白名单直连
HUB  = ("175.178.118.76", 52222) # hub echo 服务端口
LOCAL_PORT = 51920

def stun_request(conn, server, seq):
    msg = bytearray(20)
    msg[0], msg[1] = 0x00, 0x01          # Binding Request
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
s.bind(("0.0.0.0", LOCAL_PORT))
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
print(f"[local] bound 0.0.0.0:{LOCAL_PORT}")

# 1) 5 次 STUN,间隔 2s,看外部端口是否稳定
seen = []
for i in range(5):
    stun_request(s, STUN, i)
    s.settimeout(3)
    try:
        data, _ = s.recvfrom(1024)
        r = parse_stun(data)
        seen.append(r)
        print(f"[stun#{i}] external = {r[0]}:{r[1]}")
    except socket.timeout:
        print(f"[stun#{i}] timeout")
    time.sleep(2)

if seen:
    ports = {p for _, p in seen}
    print(f"[stun] 端口保持: {len(ports)==1} (distinct={sorted(ports)})")

# 2) 同一 socket 打 hub(发 3 包,间隔 3s,便于 hub 观察)
print(f"[punch] sending to hub {HUB[0]}:{HUB[1]} ...")
for i in range(3):
    s.sendto(b"PING-HUB-%d" % i, HUB)
    s.settimeout(4)
    try:
        data, addr = s.recvfrom(1024)
        print(f"[punch#{i}] hub reply: {data!r} from {addr}")
        break
    except socket.timeout:
        print(f"[punch#{i}] no reply")
    time.sleep(3)
s.close()
