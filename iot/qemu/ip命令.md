`ip` 命令来自 `iproute2` 软件包，用于显示和操作路由、网络设备、接口与隧道，是 `ifconfig`、`route`、`arp` 等传统工具的现代替代品。



## 一、命令语法

```
ip [ OPTIONS ] OBJECT { COMMAND | help }
ip [ -force ] -batch filename
```

- **OBJECT**：要操作的对象，如 `link`、`addr`、`route`、`rule`、`neigh`、`netns`、`tunnel` 等。
- **COMMAND**：对该对象执行的动作，如 `show`、`add`、`del`、`set`、`change`、`flush`。
- **help**：查看任意对象支持的完整子命令列表，例如 `ip link help`。

## 二、全局选项

| 选项              | 说明                                                     |
| :---------------- | :------------------------------------------------------- |
| `-V` / `-Version` | 显示 `ip` 工具版本并退出                                 |
| `-h` / `-human`   | 以人类可读格式输出统计值（带单位后缀）                   |
| `-s` / `-stats`   | 输出更多统计信息，可叠加使用（`-s -s` 更详细）           |
| `-d` / `-details` | 输出更详细的信息                                         |
| `-o` / `-oneline` | 每条记录输出为一行，便于 `grep` 或 `wc` 处理             |
| `-br` / `-brief`  | 简洁输出，仅显示关键字段                                 |
| `-j` / `-json`    | 以 JSON 格式输出                                         |
| `-p` / `-pretty`  | 配合 `-j` 使用，美化 JSON 输出                           |
| `-4`              | 仅操作 IPv4（等价于 `-family inet`）                     |
| `-6`              | 仅操作 IPv6（等价于 `-family inet6`）                    |
| `-B`              | 桥接协议族（`-family bridge`）                           |
| `-r` / `-resolve` | 将 IP 地址解析为主机名                                   |
| `-f <family>`     | 指定协议族：`inet`、`inet6`、`bridge`、`mpls`、`link` 等 |
| `-n <netns>`      | 在指定网络命名空间中执行命令                             |
| `-batch <file>`   | 从文件读取命令批量执行                                   |
| `-force`          | 批量模式下出错不终止                                     |

## 三、核心对象与常用命令

**查看接口**

```
ip link show                          # 显示所有接口
ip link show dev eth0                 # 显示指定接口
ip -s link show eth0                  # 显示接口统计信息
ip -br link show                      # 简洁输出
```

**启用/禁用接口**

```
ip link set dev eth0 up               # 启用
ip link set dev eth0 down             # 禁用
```

**修改接口属性**

```
ip link set eth0 mtu 1400             # 设置 MTU
ip link set eth0 address 00:11:22:33:44:55   # 修改 MAC 地址
ip link set eth0 promisc on           # 开启混杂模式
ip link set eth0 txqueuelen 1200      # 设置发送队列长度
```

**创建虚拟接口**

```
# VLAN 接口
ip link add link eth0 name eth0.100 type vlan id 100

# 网桥
ip link add name br0 type bridge

# veth 对（常用于容器/命名空间）
ip link add veth0 type veth peer name veth1

# 删除虚拟接口
ip link delete veth0
```

### 3.2 `ip addr` — IP 地址管理

**查看地址**

```
ip addr show                          # 显示所有接口的 IP 地址
ip addr show dev eth0                 # 显示指定接口
ip -4 addr show                       # 仅显示 IPv4
ip -6 addr show                       # 仅显示 IPv6
```

**添加/删除地址**

```
ip addr add 192.168.1.10/24 dev eth0          # 添加 IP
ip addr del 192.168.1.10/24 dev eth0          # 删除 IP
ip addr add 192.168.1.20/24 dev eth0 label eth0:1   # 添加别名
```

**清空地址**

```
ip addr flush dev eth0            # 清空接口上所有地址
```

### 3.3 `ip route` — 路由表管理

**查看路由**

```
ip route show                         # 显示主路由表
ip route show table all               # 显示所有路由表
ip route show table 100               # 显示指定路由表
ip route get 8.8.8.8                  # 查询到目标地址的实际路由
ip -6 route show                      # 显示 IPv6 路由
```

**添加/删除路由**

```
ip route add default via 192.168.1.1                # 添加默认路由
ip route add 10.0.0.0/8 via 192.168.1.1             # 添加目标网段路由
ip route add 172.16.0.0/16 dev eth1                 # 指定出接口
ip route replace default via 192.168.1.254           # 替换已有路由
ip route del 10.0.0.0/8                             # 删除路由
ip route del default                                 # 删除默认路由
```

### 3.4 `ip rule` — 策略路由规则

`ip rule` 决定数据包使用哪张路由表，优先级数值越小越先匹配。

```
ip rule show                                          # 显示所有规则
ip rule add from 192.168.1.0/24 table 100             # 源地址走表 100
ip rule add from 10.0.0.115 table 10 priority 100     # 指定优先级
ip rule del from 192.168.1.0/24 table 100             # 删除规则
```

### 3.5 `ip neigh` — ARP/邻居缓存管理

```
ip neigh show                         # 显示邻居表（ARP 缓存）
ip neigh show dev eth0                # 显示指定接口的邻居条目
ip neigh add 192.168.1.50 lladdr 00:11:22:33:44:55 dev eth0   # 添加静态条目
ip neigh del 192.168.1.50 dev eth0    # 删除条目
ip neigh flush all                    # 清空所有邻居缓存
ip neigh flush dev eth0               # 清空指定接口的缓存
```

### 3.6 `ip netns` — 网络命名空间

```
ip netns list                         # 列出所有命名空间
ip netns add myns                     # 创建命名空间
ip netns exec myns ip addr show       # 在命名空间内执行命令
ip netns delete myns                  # 删除命名空间
```

### 3.7 `ip tunnel` — 隧道配置

```
ip tunnel help                        # 查看隧道子命令
ip tunnel add gre0 mode gre remote 198.51.100.10 local 203.0.113.10 ttl 255
ip tunnel show                        # 显示所有隧道
ip tunnel change gre0 ttl 64          # 修改隧道参数
ip tunnel del gre0                    # 删除隧道
```