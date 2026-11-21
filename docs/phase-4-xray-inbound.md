# Xray 受控 SOCKS5 入站

首个模板适用于 Linux amd64 的 Xray `v26.10.31`，仍需匹配独立签名稳定清单中的精确制品。节点本地 root 审批监听端口、密码和单一 IPv4 TCP 目标。面板管理员只审批候选端口和配置指纹。模板固定用户 `mcui`、回环监听、密码认证及默认拒绝路由。[配置策略](./config-policy.md) · [Xray SOCKS 文档](https://xtls.github.io/config/inbounds/socks.html)

## 节点准备

1. 按[阶段 3 操作手册](./phase-3-operations.md)部署使用同版程序的 Master、签发端、Agent、Helper、`mcui-xray` 和 Xray units。安装清单批准的 `v26.10.31`。更新已有节点 unit 后运行 `systemctl daemon-reload` 和 `mcui-xray recover`。
2. 确认 systemd 的 D-Bus 系统总线可用。节点 root 创建专用命名空间 `/run/netns/mcui-xray`，启用该命名空间的回环接口，并按部署拓扑配置通向所批准目标的受限路由与防火墙。测试可用 `ip netns add mcui-xray` 和 `ip -n mcui-xray link set lo up` 创建命名空间。持续部署应由本地 systemd 依赖在 Xray 恢复前重新建立该命名空间和网络规则。
3. 在节点的 `/etc/systemd/system/mcui-xray.service.d/` 添加本地 drop-in，用精确地址替换示例占位符并执行 `systemctl daemon-reload`。保留默认 `IPAddressDeny=any`、`PrivateNetwork=yes`、动态用户和私有凭据加载设置。预检 unit 保持默认独立网络和无允许地址。迁移目标时，在新修订提交前保留上一个已提交目标的网络许可，以便启动回滚。

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

面板显示候选与已应用配置的摘要、端口和修订号。完整配置和密码仅在节点以私有文件保留，用于运行和事务恢复。用户级统计、额度、订阅及通用入站模板仍在阶段 4 工作列表中。[工作流](./phased-development-workflow.md#阶段-4xray-完整业务闭环与最小演示)
