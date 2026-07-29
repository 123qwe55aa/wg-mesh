# wg-mesh

Dynamic WireGuard mesh VPN — P2P direct connections with relay fallback, inspired by Tailscale.

```
                    ┌── LAN WireGuard ──┐
                    │                   │
              node-a                  node-b
          10.200.200.2             10.200.200.3
               │                       │
               └──────┬── hub ────────┘
                    10.200.200.1
```

- **控制面**: PEX gossip + Kademlia DHT over TCP（节点发现、路由交换）
- **数据面**: WireGuard UDP（直连打洞，打不通走中继）
- **打洞**: STUN 探测公网地址 + 两端主动握手穿过 NAT
- **中继**: 任意节点可做 hub，转发流量给无法直连的 peer

## 架构

```
wg-meshd（控制面）
├── pkg/pex/     PEX gossip 协议 — 定期交换已知 peer 列表
├── pkg/dht/     Kademlia DHT — 分布式哈希表发现节点
├── pkg/nat/     STUN 客户端 — 探测公网 IP:Port
├── pkg/uapi/    WireGuard 控制 — 通过 `wg` 命令加/删 peer
└── pkg/mesh/    状态管理 — 追踪所有 peer 的连接状态

wireguard-go / 内核 WireGuard（数据面）
    通过 wg-meshd 自动配置 peer → UDP 打洞 → 直连
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
```

### 2. 部署 Hub（需有公网 IP 的服务器）

Hub 是 mesh 的「种子节点」，负责 Bootstrap 和中继。

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

# 启动 wg-meshd（作为 seed）
./wg-meshd-linux \
  --public-key "$(cat /etc/wireguard/hub.pub)" \
  --interface wg0

# （推荐）systemd 服务
cat > /etc/systemd/system/wg-meshd.service << 'EOF'
[Unit]
Description=wg-meshd
After=network.target

[Service]
ExecStart=/usr/local/bin/wg-meshd --public-key $(cat /etc/wireguard/hub.pub) --interface wg0
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
systemctl enable --now wg-meshd
```

> **注意**: Hub 需开放以下端口：
> - `51820/udp` — WireGuard 数据
> - `51821/tcp` — PEX gossip（可选，不开则无自动发现）
> - `51822/tcp` — DHT bootstrap（可选，不开则需 `--vps` 手动指定）

### 3. 部署节点（macOS）

```bash
# 安装 wireguard-go
brew install wireguard-tools wireguard-go

# 生成密钥
wg genkey | tee /tmp/node.key | wg pubkey > /tmp/node.pub

# 创建 LaunchDaemon
sudo tee /Library/LaunchDaemons/com.wireguard.go.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.wireguard.go</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/homebrew/opt/wireguard-go/bin/wireguard-go</string>
        <string>-f</string>
        <string>utun10</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF
sudo launchctl load /Library/LaunchDaemons/com.wireguard.go.plist

# 配置 WG 接口
sudo wg set utun10 private-key /tmp/node.key
sudo ifconfig utun10 inet 10.200.200.X/24 10.200.200.X   # X=2,3,4...
sudo route add -net 10.200.200.0/24 -interface utun10

# sudoers 免密（让 wg-meshd 能加 peer）
echo "$USER ALL=(ALL) NOPASSWD: /opt/homebrew/bin/wg" | sudo tee -a /etc/sudoers.d/wireguard
```

#### 启动 wg-meshd

**方式 A：Hub 有公网 IP + DHT/PEX 端口开放**

```bash
./wg-meshd-macos \
  --public-key "$(cat /tmp/node.pub)" \
  --interface utun10 \
  --seed '<hub-pubkey>@<hub-ip>:51822' \
  --mesh-port 51821
```

**方式 B：Hub 在防火墙后（如腾讯云），只开放了 WG 端口**

```bash
# 先用 SSH 隧道打通控制面
ssh -L 51822:127.0.0.1:51822 -L 51821:127.0.0.1:51821 -Nf user@hub-ip

# 启动 wg-meshd，通过隧道连 DHT，直连打洞用 WG 端口
./wg-meshd-macos \
  --public-key "$(cat /tmp/node.pub)" \
  --interface utun10 \
  --seed '<hub-pubkey>@127.0.0.1:51822' \
  --vps '<hub-ip>:51820' \
  --mesh-port 51821
```

**方式 C：节点间已有其他连接（如局域网），手动添加**

```bash
# 直接配 WireGuard peer（不依赖 DHT）
sudo wg set utun10 peer <other-node-pubkey> \
  endpoint <other-node-ip>:<other-node-port> \
  allowed-ips 10.200.200.Y/32 \
  persistent-keepalive 25
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

# sudoers 免密（让 wg-meshd 能加 peer）
echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/wg" | sudo tee -a /etc/sudoers.d/wireguard

# 启动 wg-meshd
./wg-meshd-linux \
  --public-key "$(cat /tmp/node.pub)" \
  --interface wg0 \
  --seed '<hub-pubkey>@<hub-ip>:51822' \
  --vps '<hub-ip>:51820' \
  --mesh-port 51821
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--public-key` | — | **必填**. 本节点的 WireGuard 公钥 |
| `--interface` | `wg0` | WireGuard 接口名（macOS 通常为 `utun10`） |
| `--seed` | `""` | 种子节点列表，格式 `pubkey@ip:port,pubkey@ip:port` |
| `--vps` | `""` | Hub 的公网 WG 地址（`ip:port`），覆盖 seed 的 endpoint 用于打洞 |
| `--mesh-port` | `51821` | PEX 监听端口，DHT 自动用 `mesh-port+1` |
| `--stun` | `stun.l.google.com:19302` | STUN 服务器地址 |

## 工作原理

### 节点发现

1. **Bootstrap**: 新节点连接种子（seed）节点的 DHT（`:51822/tcp`）
2. **DHT**: 发送 `FIND_NODE`，种子返回已知节点列表
3. **PEX**: 每隔 30s 向已连接的 peer 广播自身已知节点列表
4. **扩散**: 新加入的节点信息逐跳传播到整个 mesh

### NAT 打洞

1. **STUN**: 各节点通过 STUN 探测自己的公网 IP:Port
2. **端点交换**: 通过 DHT/PEX 互相传递公网端点
3. **握手**: 双方互加 WireGuard peer → 自动发起握手
4. **直连**: 握手成功 → UDP 直连通道建立
5. **回退**: 握手失败 → 流量通过 hub 中继

### 路由优先级

WireGuard 按 `allowed-ips` 最长前缀匹配：

```
10.200.200.3/32  → 直连 peer A（最优先）
10.200.200.0/24  → hub 中继（兜底）
```

## 网络拓扑

| 节点 | 角色 | IP | 说明 |
|------|------|-----|------|
| hub | 种子 + 中继 | `10.200.200.1` | 公网服务器 |
| node-a | 普通节点 | `10.200.200.2` | 桌面/笔记本 |
| node-b | 普通节点 | `10.200.200.3` | 桌面/笔记本 |

所有节点的 `allowed-ips` 应包含 `10.200.200.0/24`，hub 需允许所有节点 IP：

```bash
# Hub 上添加每个节点的 peer
sudo wg set wg0 peer <node-pubkey> allowed-ips 10.200.200.X/32 persistent-keepalive 25
```

## 持久化配置

### OpenWrt / PassWall2 旁路

如果 Mac 走 OpenWrt 透明代理，需要把 hub IP 加入直连：

```bash
# 临时（nftables）
nft add element inet passwall2 psw2_direct { <hub-ip> }

# 永久（add_direct_ips.sh）
echo 'nft add element inet passwall2 psw2_direct { <hub-ip> } 2>/dev/null' \
  >> /usr/share/passwall2/add_direct_ips.sh
```

### Hub 自动添加新节点

wg-meshd 在 DHT/PEX 中发现新 peer 时会自动调用 `wg set` 加入 WireGuard。需确保 `wg` 命令免密 sudo。

## 故障排查

```bash
# 检查 WireGuard 状态
sudo wg show

# 检查 wg-meshd 日志
journalctl -u wg-meshd              # systemd
tail -f /tmp/wireguard-go.log       # macOS wireguard-go

# 测试连接
ping 10.200.200.1                   # 到 hub
ping 10.200.200.X                   # 到其他节点

# 查看 WG 握手状态
sudo wg show | grep handshake       # 有 latest handshake 说明打通了
```

## 依赖

- [WireGuard](https://www.wireguard.com/) — 数据面
- [wireguard-go](https://git.zx2c4.com/wireguard-go/) — macOS 用户态 WireGuard
- Go 1.21+ — 编译

## License

MIT
