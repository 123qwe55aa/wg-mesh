# wg-mesh

Dynamic WireGuard mesh VPN — P2P direct connections with STUN auto-discovery and relay fallback.

```
                    ┌── P2P WireGuard ──┐
                    │      (NAT3/4)     │
              node-a ◄─────────────────► node-b
          10.200.200.2    or relay   10.200.200.3
               │                       │
               └──────── hub ──────────┘
                    10.200.200.1
                (seed + DHT + relay)
```

- **控制面**: Kademlia DHT over TCP（节点发现 + 路由交换 + 状态报告）
- **数据面**: WireGuard UDP（直连打洞，打不通走 hub 中继）
- **打洞**: STUN 自动探测公网地址 → 双端注册 LAN + Public 地址 → NAT 打洞
- **中继**: Hub 转发流量给无法直连的 peer，看门狗自动切换

## 新特性

| 特性 | 说明 |
|------|------|
| **双端注册** | 每个节点自动注册 LAN 地址 + STUN 公网地址到 DHT |
| **STUN 自动发现** | 不传 `--wg-endpoint` 时自动 STUN 发现公网地址注册 |
| **换网复写** | DHT contact 更新而非跳过，换网后自动刷新路由表 |
| **Hub 通知** | Hub 在 peer 注册/更新时触发回调 + 日志 |
| **状态报告** | 节点成功连接后向 hub 发送 `MsgReportState` |
| **定时刷新** | 每 5 分钟 DHT refresh 自动同步 endpoint 变更 |
| **REUSEPORT** | 优先直接绑定 WG 端口做 STUN（macOS），获得精确 CGNAT 映射 |

## 架构

```
wg-meshd（控制面 — TCP）
├── pkg/pex/     PEX gossip 协议 — peer exchange
├── pkg/dht/     Kademlia DHT — 分布式节点发现 + 状态报告
├── pkg/nat/     STUN 客户端 — 探测公网 IP:Port
├── pkg/uapi/    WireGuard 配置 — 通过 `wg` 加/删 peer
└── pkg/mesh/    状态管理 — 追踪 peer 连接状态

wireguard-go / 内核 WireGuard（数据面 — UDP）
    通过 wg-meshd 自动配置 peer → 双端打洞 → 直连 / 中继兜底
```

### 完整上线流程

```
Peer 上线:
  ① wg show dump 取 WG 监听端口（如 62784）
  ② STUN → 发现公网地址 112.97.66.3:CGNAT_PORT
  ③ DHT 注册: {Endpoint: 192.168.30.X:62784,
                PublicEndpoint: 112.97.66.3:CGNAT_PORT}
  ④ Hub 存下两套地址 + 触发回调

Peer 换网:
  ① 同上 STUN 发现新地址
  ② DHT bootstrap → hub 执行 insert()
  ③ 旧 contact 存在 → 复写 endpoint + publicEndpoint ✅
  ④ Hub 触发 onPeerDiscovered → 更新 WG 配置

查到对方:
  ① DHT 返回 {LAN, Public}
  ② callback 用 PublicEndpoint 设 WG endpoint
  ③ 同网 → WG roaming 自动切 LAN 地址
  ④ 跨网 → 公网地址打洞
  ⑤ 都不通 → hub relay 兜底
  ⑥ 成功 → 向 hub 发送 MsgReportState("connected")

三方可见:
  Hub 日志:
    dht hub registered peer update pk=... ep=... public_ep=...
    dht peer state report from=... peer=... state=connected
  Lisa 日志:
    dht discovered peer pk=... ep=... public_ep=...
    dht peer added to wireguard pk=... ep=public_ep
    dht state sent peer=... state=connected
  Toby 日志: (5min refresh 后)
    dht discovered peer pk=... ep=... public_ep=...
    dht peer added to wireguard pk=... ep=public_ep
```

## 快速开始

### 1. 编译

```bash
git clone https://github.com/123qwe55aa/wg-mesh.git
cd wg-mesh

# Linux amd64
GOOS=linux GOARCH=amd64 go build -o wg-meshd-linux ./cmd/wg-meshd/

# macOS arm64
GOOS=darwin GOARCH=arm64 go build -o wg-meshd-macos ./cmd/wg-meshd/

# macOS amd64
GOOS=darwin GOARCH=amd64 go build -o wg-meshd-macos-intel ./cmd/wg-meshd/
```

### 2. 部署 Hub（需有公网 IP 的服务器）

Hub 是 mesh 的种子节点，负责 DHT bootstrap、peer 路由和中继转发。

```bash
# 安装 WireGuard
apt install wireguard     # Debian/Ubuntu

# 生成密钥
wg genkey | tee /etc/wireguard/hub.key | wg pubkey > /etc/wireguard/hub.pub

# 创建 WG 接口
ip link add wg0 type wireguard
wg set wg0 private-key /etc/wireguard/hub.key
ip addr add 10.200.200.1/24 dev wg0
ip link set wg0 up

# 启动 wg-meshd（Hub 不需要 --seed，本身是种子）
# Hub 的 --wg-endpoint 留空 → 自动 STUN 发现公网地址
./wg-meshd-linux \
  --public-key "$(cat /etc/wireguard/hub.pub)" \
  --interface wg0

# systemd 服务
cat > /etc/systemd/system/wg-meshd.service << 'EOF'
[Unit]
Description=wg-mesh daemon - dynamic WireGuard mesh control
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wg-meshd --public-key $(cat /etc/wireguard/hub.pub) --interface wg0
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl enable --now wg-meshd
```

> **端口要求**（Hub）:
> - `51820/udp` — WireGuard 数据面
> - `51822/tcp` — DHT bootstrap（节点发现必需）
> - `51821/tcp` — PEX gossip（可选，不开则无主动散布）

### 3. 部署节点（macOS）

```bash
# 安装 wireguard-go
brew install wireguard-tools wireguard-go

# 生成密钥
wg genkey | tee /tmp/node.key | wg pubkey > /tmp/node.pub

# 启动 wireguard-go（也可用 LaunchDaemon，见示例）
sudo wireguard-go utun10
sudo wg set utun10 private-key /tmp/node.key
sudo wg set utun10 listen-port 62784
sudo ifconfig utun10 inet 10.200.200.X/24 10.200.200.X   # X=2,3,4...
sudo route add -net 10.200.200.0/24 -interface utun10

# sudoers 免密（让 wg-meshd 能加 peer）
echo "$USER ALL=(ALL) NOPASSWD: /opt/homebrew/bin/wg" | sudo tee -a /etc/sudoers.d/wireguard
```

#### 启动 wg-meshd（带自动发现）

**不传 `--wg-endpoint`** → 自动 STUN 发现公网地址注册到 DHT：

```bash
./wg-meshd-macos \
  --public-key "$(cat /tmp/node.pub)" \
  --interface utun10 \
  --seed '<hub-pubkey>@<hub-ip>:51822' \
  --vps '<hub-ip>:51820' \
  --relay '<hub-ip>:51820' \
  --mesh-port 51821
```

**显式指定 endpoint**（跳过 STUN）：

```bash
./wg-meshd-macos \
  --public-key "$(cat /tmp/node.pub)" \
  --interface utun10 \
  --seed '<hub-pubkey>@<hub-ip>:51822' \
  --vps '<hub-ip>:51820' \
  --wg-endpoint '192.168.30.X:62784' \
  --relay '<hub-ip>:51820' \
  --mesh-port 51821
```

### 4. 部署节点（Linux）

```bash
# 安装 WireGuard
apt install wireguard

# 生成密钥
wg genkey | tee /tmp/node.key | wg pubkey > /tmp/node.pub

# 创建 WG 接口
ip link add wg0 type wireguard
wg set wg0 private-key /tmp/node.key
ip addr add 10.200.200.X/24 dev wg0
ip link set wg0 up

# sudoers 免密
echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/wg" | sudo tee -a /etc/sudoers.d/wireguard

# 启动 wg-meshd
./wg-meshd-linux \
  --public-key "$(cat /tmp/node.pub)" \
  --interface wg0 \
  --seed '<hub-pubkey>@<hub-ip>:51822' \
  --vps '<hub-ip>:51820' \
  --relay '<hub-ip>:51820' \
  --mesh-port 51821
```

### 5. Hub 添加节点到 WG

wg-meshd 会自动通过 DHT 发现新节点并调用 `wg set`，但在 hub 上仍需配置静态 AllowedIPs：

```bash
# Hub 上添加节点的 /32 路由（DHT 可以自动设 peer，但 AllowedIPs 需要手动或通过种子配置）
sudo wg set wg0 peer <node-pubkey> allowed-ips 10.200.200.X/32 persistent-keepalive 25
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--public-key` | — | **必填**. 本节点的 WireGuard 公钥 |
| `--interface` | `wg0` | WireGuard 接口名（macOS 通常 `utun10`） |
| `--seed` | `""` | 种子节点列表，格式 `pubkey@ip:port,pubkey@ip:port` |
| `--vps` | `""` | Hub 公网 WG 地址（`ip:port`），作为 DHT endpoint 兜底 + 打洞目标 |
| `--wg-endpoint` | `""` | 本节点 WG endpoint，留空则自动 STUN 发现公网地址（推荐） |
| `--relay` | `""` | Hub 中继地址，开启后 watchog 自动切 P2P/中继 |
| `--hub-intra-ip` | `""` | Hub 内网 mesh IP，用于 DHT TCP 直连被拦时的隧道降级 |
| `--mesh-port` | `51821` | PEX 监听端口，DHT 自动用 `mesh-port+1` |
| `--stun` | `stun.l.google.com:19302` | STUN 服务器地址 |
| `--handshake-timeout` | `2m` | P2P 握手超时时间（超时后切中继） |
| `--handshake-interval` | `15s` | 握手检查间隔 |
| `--restore-interval` | `5m` | P2P 恢复尝试间隔 |

## 工作原理

### 节点发现

1. **Bootstrap**: 新节点通过 TCP 连接种子（seed）节点的 DHT（`:51822/tcp`）
2. **注册**: 发送 `FIND_NODE`，携带本节点 WG endpoint + PublicEndpoint
3. **路由**: 种子返回已知节点列表（按 XOR 距离排序），最多 8 个
4. **扩散**: PEX gossip 定期向已连接 peer 散布已知路由
5. **更新**: contact 已存在时复写 endpoint（换网自动刷新）

### NAT 打洞

1. **STUN 发现**: 各节点通过 STUN 探测公网 `IP:CGNAT_PORT`
   - 优先 `SO_REUSEPORT` 绑定 WG 端口 → 精确 CGNAT 映射
   - 降级到独立端口 STUN → 至少拿到公网 IP
2. **双端注册**: 同时注册 LAN 地址 + 公网地址到 DHT
3. **端点交换**: 通过 DHT 获取对端两套地址
4. **握手**: 用 PublicEndpoint 设 WG peer → 自动发起握手
5. **直连**: 握手成功 → UDP 直连通道建立
6. **回退**: 握手失败 → 流量通过 hub 中继（`/24` 兜底）

### 路由优先级

WireGuard 按 `allowed-ips` 最长前缀匹配：

```
peer: 10.200.200.2/32 → Lisa P2P 直连（最优先）
peer: 10.200.200.0/24 → Hub 中继（兜底）
```

看门狗监控握手状态，P2P 超时 2min 后删除 `/32` peer，流量自动回落中继。

### 状态报告

节点成功将 peer 加入 WG 后，通过 DHT 向 hub 发送 `MsgReportState`，hub 记录日志：

```
dht peer state report from=Lisa peer=Toby state=connected endpoint=112.97.66.3:PORT_T
```

## 网络拓扑参考

| 节点 | 角色 | Mesh IP | 说明 |
|------|------|---------|------|
| hub | 种子 + 中继 | `10.200.200.1` | 公网服务器，开放 51820/udp + 51822/tcp |
| node-a | 普通节点 | `10.200.200.2` | 桌面/笔记本，NAT3/4 后 |
| node-b | 普通节点 | `10.200.200.3` | 桌面/笔记本，NAT3/4 后 |

## 持久化配置

### OpenWrt / PassWall2 旁路

如果 Mac 走 OpenWrt 透明代理，需要把 hub IP 加入直连：

```bash
# 临时
nft add element inet passwall2 psw2_direct { <hub-ip> }

# 永久
echo 'nft add element inet passwall2 psw2_direct { <hub-ip> } 2>/dev/null' \
  >> /usr/share/passwall2/add_direct_ips.sh
```

### FORWARD 规则（路由器吞回包）

```bash
# 放行 VPS 回包
iptables -I FORWARD -s <hub-ip> -p udp -j ACCEPT
```

## 故障排查

```bash
# 检查 WireGuard 状态
sudo wg show

# 检查 wg-meshd 日志
journalctl -u wg-meshd                    # systemd（Linux）
tail -f /tmp/wg-lisa-up.log               # macOS（LaunchDaemon）

# 测试连接
ping 10.200.200.1                         # 到 hub
ping 10.200.200.X                         # 到其他节点

# 查看 WG 握手状态
sudo wg show | grep handshake             # 有 latest handshake 说明打通了

# 查看 DHT 日志关键词
journalctl -u wg-meshd | grep -i 'dht'    # DHT 发现/注册/状态
journalctl -u wg-meshd | grep -i 'state'  # 状态报告
journalctl -u wg-meshd | grep -i 'stun'   # STUN 自动发现
```

### 日志解读

```
# STUN 自动发现成功
auto-discovered public IP from STUN public_ep=112.97.66.3:37863 lan_ep=192.168.30.207:58715

# Hub 收到 peer 注册
dht hub registered peer update pk=Ua4YA5... ep=192.168.30.207:58715 public_ep=112.97.66.3:37863

# 节点发现对端
dht discovered peer pk=pggw7P... ep=192.168.30.243:62784 public_ep=112.97.66.3:PORT_T

# 成功加入 WG
dht peer added to wireguard pk=pggw7P... ep=112.97.66.3:PORT_T public_ep=112.97.66.3:PORT_T

# 状态报告
dht peer state report from=Lisa peer=Toby state=connected endpoint=112.97.66.3:PORT_T
```

## 依赖

- [WireGuard](https://www.wireguard.com/) — 数据面
- [wireguard-go](https://git.zx2c4.com/wireguard-go/) — macOS 用户态 WireGuard
- Go 1.21+ — 编译

## License

MIT
