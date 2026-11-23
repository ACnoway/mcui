# Xray 受控 SOCKS5 入站

面板管理模式允许单管理员给节点预先批准的端口分配用户。使用该模式时，先完成本页的节点准备第 1–3 步，再建立节点目录和面板草稿。节点、Master、Agent、Helper 和独立签发服务须使用支持该模式的版本。

## 面板管理入站与授权

1. 在节点 root 的 `/etc/mcui-xray` 目录下创建 `managed-inbounds.json`，目录和文件分别为 `root:root`、`0700` 和 `0600`。发布摘要、目的 IPv4 和 TCP 端口须匹配已审核制品和节点网络策略。每个用户分别生成 32 字节随机密码，再按无填充 Base64URL 编码。

   ```json
   {
     "release_sha256": "<已安装发布制品 SHA-256>",
     "ports": [1080, 1081],
     "credentials": {
       "alice": "<Alice 的随机密码>",
       "bob": "<Bob 的随机密码>"
     },
     "destination_ip": "<批准的公网 IPv4>",
     "destination_port": 443
   }
   ```

2. 在节点详情的「SOCKS5 入站授权草稿」中勾选各端口允许的用户名并保存。未授予用户的端口不监听。最多启用 4 个端口、登记 8 个用户名并同时分配 16 条端口授权。用户名以小写字母开头，最多 24 个字符，可含小写字母、数字、连字符和下划线。
3. 等待节点心跳并刷新。核对已应用授权、草稿和节点报告的 SHA-256，通过「下发受控 SOCKS5 入站」确认并完成 MFA 复验。签发后草稿可以继续编辑，已签发任务仍按当时批准的授权执行。以成功任务及节点上报的已应用修订确认变更生效。
4. 撤销授权时取消对应选项并重新下发。保存并应用空草稿会移除全部监听。轮换密码时由节点 root 原子更新目录文件，通知客户端，再用相同授权重新预览并下发新摘要。仅编辑草稿或节点文件不会中断当前连接。应用配置会重启运行中的 Xray，撤销从成功应用的新修订开始生效。

节点目录存在时启用面板管理模式。移除该文件后可由原单用户模式准备并签发新的配置，当前已提交配置仍可运行。目录读错、策略变化或摘要不匹配时停止下发该候选，保留上一次提交的配置。面板、任务和审计只包含用户名、端口、状态和摘要。密码由节点 root 保管，通过部署方的安全渠道交给授权客户端。

## 节点本地单用户模板

首个模板适用于 Linux amd64 的 Xray `v26.10.31`，仍需匹配独立签名稳定清单中的精确制品。节点本地 root 审批监听端口、密码和单一 IPv4 TCP 目标。面板管理员只审批候选端口和配置指纹。模板固定用户 `mcui`、回环监听、密码认证及默认拒绝路由。[配置策略](./config-policy.md) · [Xray SOCKS 文档](https://xtls.github.io/config/inbounds/socks.html)

## 节点准备

1. 按[阶段 3 操作手册](./phase-3-operations.md)部署使用同版程序的 Master、签发端、Agent、Helper、`mcui-xray` 和 Xray units。安装清单批准的 `v26.10.31`。更新已有节点 unit 后运行 `systemctl daemon-reload` 和 `mcui-xray recover`。
2. 节点 root 创建专用命名空间 `/run/netns/mcui-xray`，启用该命名空间的回环接口，并按部署拓扑配置通向所批准目标的受限路由与防火墙。测试可用 `ip netns add mcui-xray` 和 `ip -n mcui-xray link set lo up` 创建命名空间。持续部署应由本地 systemd 依赖在 Xray 恢复前重新建立该命名空间和网络规则。
3. 在节点的 `/etc/systemd/system/mcui-xray.service.d/` 添加本地 drop-in，用精确地址替换示例占位符并执行 `systemctl daemon-reload`。保留默认 `IPAddressDeny=any`、`PrivateNetwork=yes`、动态用户和固定标准输入设置。预检 unit 保持默认独立网络和无允许地址。迁移目标时，在新修订提交前保留上一个已提交目标的网络许可，以便启动回滚。

```ini
[Service]
NetworkNamespacePath=/run/netns/mcui-xray
IPAddressAllow=127.0.0.1/32
IPAddressAllow=<批准的目标 IPv4>/32
```

4. 确认 `/etc/mcui-xray` 为 `root:root`、`0700` 的真实目录。在其中以 `root:root`、`0600` 创建 `controlled-inbound.json`。将示例字段替换为精确已安装制品摘要、1024..65535 的监听端口、32 字节随机值的无填充 Base64URL 密码、批准的 IPv4 及 TCP 端口。可用 `openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'` 生成测试密码。密码仅保存在节点和授权客户端。

```json
{
  "release_sha256": "<已安装发布制品 SHA-256>",
  "listen_port": 1080,
  "password": "<无填充 Base64URL 随机密码>",
  "destination_ip": "<批准的公网 IPv4>",
  "destination_port": 443
}
```

## 下发、验证与恢复

1. 等待节点心跳刷新。在节点的「Xray 远程管理」选择「下发受控 SOCKS5 入站」，核对候选端口和 SHA-256，完成确认及当前 MFA。选项需要有效签名清单包含当前制品，并且节点汇报的候选内容有变化。
2. 在面板刷新任务结果和已应用修订。运行中的节点切换时会重启 Xray。原先已停止的节点会短暂启动候选作健康检查，然后恢复停止状态。
3. 让测试客户端在同一专用命名空间中访问 `127.0.0.1:<监听端口>`，用用户 `mcui` 和本地密码请求批准的字面 IPv4 与端口。分别验证错误密码、目标端口不匹配和域名请求被拒绝。客户端测试凭据使用受限权限的本地配置文件传入。
4. 配置预检、策略摘要或授权校验失败时，任务返回 `FAILED`。候选启动失败且成功恢复时返回 `ROLLED_BACK`。未决事务用原签名任务对账，必要时由节点 root 执行 `mcui-xray recover`。移除候选策略文件会阻止新的下发。停用运行中的入站可在面板停止 Xray。跨版本切换成功后使用新版本的引导配置。

面板显示候选和已应用配置的摘要与端口，并显示已应用的修订号。完整配置和密码仅在节点以私有文件保留，用于运行和事务恢复。用户级统计、额度及订阅仍在阶段 4 工作列表中。[工作流](./phased-development-workflow.md#阶段-4xray-完整业务闭环与最小演示)

## 隔离验收记录

2026-11-21 在 `ro` 从 `/root/mcui` 建立临时检出验证提交 `1972662`。数据面使用无外网网卡的 Debian 13 amd64 QEMU 客户机，内核 `6.12.107+deb13-cloud-amd64`，systemd `257.13-1~deb13u1`。官方 Xray `v26.10.31` amd64 ZIP 的 SHA-256 为 `e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214`。[官方发布页](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31)

| 检查 | 结果 |
|---|---|
| 面板签发与投递 | 集成测试核对配置指纹、发布清单、双签名、确认与 MFA。候选发生变化和旧 Agent 领取均被拒绝，支持配置的 Agent 可领取并回报。 |
| 真实 Xray 数据面 | 使用系统自带 systemd 运行 Xray 和隔离预检。curl 通过认证 SOCKS5 获得授权 IPv4 TCP 测试端点的预期 HTTP 内容。错误密码、未授权端口、域名和回环地址作为目的均被拒绝。 |
| 启停与恢复 | 占用候选监听端口触发启动失败。旧配置、正在运行状态及原密码恢复，原客户端再次连通。对账返回保存的 `ROLLED_BACK`。停止后连接失败，启动后恢复。 |
| 构建与回归 | `scripts/check-static.sh`、相关 Go 包的竞态检查、`scripts/build-runtime-release.sh` 和两个发布 ZIP 的 SHA-256 核验均通过。arm64 完成构建和包摘要核验。 |

### 面板入站授权验证（2026-11-23）

在 `ro` 从 `/root/mcui` 建立隔离检出，验证提交 `b17281b`。环境为 Debian 13 amd64、内核 `6.12.107+deb13-cloud-amd64`、systemd `257.13-1~deb13u1`。使用 Go `1.27.4`、Node.js `26.13.1`、pnpm `12.17.0`。实际连接使用上述官方 Xray `v26.10.31` amd64 制品并重新核对 ZIP 的 SHA-256。

| 检查 | 结果 |
|---|---|
| 草稿与任务 | `scripts/check-static.sh` 通过。集成测试覆盖节点范围、CSRF、草稿版本冲突、重复保存、未预览拒绝、独立签发及旧 Agent 隔离。原单用户签发和双签名跨实现向量通过。 |
| 真实连接与撤销 | 在无默认路由的隔离网络命名空间，以生成的配置启动真实 Xray。两个用户可分别通过有授权的端口取得 TCP 测试端点的 HTTP 内容。错误密码、未授权端口组合和未批准目标端口被拒绝。重新加载撤销配置后，原用户无法连接，其余用户仍可连接。空草稿通过 Xray 预检并关闭全部监听。 |
| 运行时事务 | Go 运行时测试覆盖凭据变化时拒用旧摘要、空草稿提交及旧配置启动失败回滚。真实连接验证使用独立 Xray 进程，systemd 故障回滚实机证据沿用上面的单用户验收。 |
| 竞态与发布包 | `go test -race -count=1` 通过 Agent、任务执行、Helper、签发、主控、协议、投递、Xray 配置和运行时包。Runtime 的 amd64/arm64 ZIP、Master 双架构安装包及其 SHA-256 校验均通过。arm64 完成构建和制品校验。 |
