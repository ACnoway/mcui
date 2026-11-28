# MCUI

轻量化分布式多节点、多内核代理管理面板（Master + Zero-Port Agent 架构）。

## 核心特性

- **双静态单二进制**：纯 Go 编译（`CGO_ENABLED=0`），仅 `mcui-master`（内嵌前端 SPA + 管理 API + 聚合订阅）与 `mcui-agent`（无状态执行面）。
- **Agent 零监听端口**：Agent 通过出站 WebSocket 主动连接 Master 并建立 `Yamux` 双向多路复用隧道，节点服务器无需开放任何额外管理端口，天然穿透 NAT 与防火墙。
- **按需安装 Core**：新节点裸装 Agent 时默认不带任何代理内核；由主控界面一键下发指定版本 `Xray-core` 安装指令（自动校验 SHA-256 与冒烟测试），随后再配置入站节点。
- **全局客户端跨节点绑定**：对齐 `3x-ui` 多节点体验，客户端仅在 Master 定义一次，自由勾选绑定多台节点的入站，统一统计配额/到期时间并生成单一聚合订阅链接（`/sub/{subId}`）。
- **现代轻量前端**：React 19 + Ant Design 6 + TanStack Query + TypeScript，支持亮/暗色模式与 WebSocket 实时状态推送。

## 构建与测试

```bash
# 编译前端并内嵌构建 mcui-master 与 mcui-agent 静态二进制
make build

# 运行全量竞态测试（含裸 Agent 注册 -> 远程下发安装 Xray -> 入站下发 -> 流量汇总 -> 订阅生成端到端测试）
make test
```

## 快速启动

```bash
# 启动主控（默认监听 :2053，初始账号密码 admin / admin，可通过 MCUI_ADMIN_USER / MCUI_ADMIN_PASS 指定）
./bin/mcui-master -addr :2053 -db ./data/mcui.db -bin-dir ./bin
```

登录面板后：
1. 在 **「节点与内核」** 点击「添加节点」，复制生成的一键命令到节点机器执行（自动裸装 `mcui-agent` 并建立零端口反向连接）。
2. 点击在线节点打开详情抽屉，选择官方版本点击 **「下发安装 Xray」**。
3. 在 **「入站管理」** 为该节点创建 VLESS-Reality / Trojan / VMess / Shadowsocks 入站。
4. 在 **「全局客户端」** 创建客户并勾选任意节点的入站，一键复制聚合订阅链接或二维码。
