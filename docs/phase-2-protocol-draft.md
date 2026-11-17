# 阶段 2 状态任务协议（开发基线）

用户于 2026-11-17 在会话中批准下述只读 V2 方案作为阶段 2 开发基线；这不构成生产上线或阶段退出批准，也不是独立安全评审记录。本文描述 `internal/protocol/v2.go` 和 `internal/protocol/testdata/protocol-v2.json` 中的互操作协议，不修改或替代已冻结的 V1 基线。Admin 状态任务 API、隔离 signer、Agent mTLS 投递/ACK、pending cancel、expired skip 和 Helper 固定只读执行已有运行时实现；整体构建、端到端安全验收和正式阶段退出仍须完成。具体边界见[阶段 2 进度](./phase-2-progress.md)。

## 提议的状态任务

- 域为 ASCII `MCUI-TASK-V2` 后接一个换行字节；其余编码遵循 V1 的严格 JSON、JCS 和 Ed25519 基线。V1/V2 域不同，签名不可互换。
- 严格只允许 `schema_version: 2` 和 `operation: core.status`。通用字段及节点内连续序号、时间上限沿用 V1 约束；`payload` 唯一字段 `core` 为 `xray`、`sing-box` 或 `mita`。
- `step` 仅有 `step_id`、`parameters`、`artifact_sha256`、`architecture`、`expected_state`。唯一允许的步骤 ID 为 `core.status`；`parameters` 只包含 `core` 且须等于 `payload.core`。
- **已批准的只读语义**：只读状态查询不涉及制品或架构，这两个字段使用字面值 `not-applicable`，它不是有效摘要或架构，也不授权制品；`expected_state` 固定为 `observe`，不授权改变状态。这仅适用于本次批准的状态查询，不是对后续安装、升级或配置操作的通用设计。
- 无额外字段；不允许请求提供 shell、路径、URL、unit、脚本或 argv。当前 Helper 将签名 Core 精确映射到 `xray.service`、`sing-box.service` 或 `mita.service`，并只调用固定的 `systemctl show` 属性集合。该实现仍需真实 Linux/service 沙箱和越权测试。

## 草案不提供的安全保证

`VerifyV2Task` 仅检查草案结构和调用方传入的公钥对应的签名。它不选择或验证受信密钥及用途，不检查本机身份、当前可信时间、序号、审批、撤销、对端凭据或持久化重放账本，也不执行任何动作。签名正确不等于具有执行授权。

现有角色文档对高危任务发起人的要求仍见[权限基线](./panel-authz.md)与本文件第 5.2 节。**本阶段已决定：只读 `core.status` 查询不单独审批**；Master 实现逐请求验证 `security_admin`/`operator` 身份、节点对象范围及只读操作权限并写授权审计。此决定不适用于后续高危任务。独立密钥生产保管流程、外部可信时钟和跨数据库恢复检查点仍未落实。

## 验证与待办

共享向量使用公开测试 seed，严禁用于生产。Go 测试和 `scripts/verify-protocol-v2-vectors.mjs` 对同一组签名向量和反例进行解析及签名校验；常规检查脚本运行两者。向量通过只能证明所测互操作情况，不等于完整规范或系统安全验收通过。V1 cancel/skip 与 V2 状态任务分开签名：当前只实现未开始状态任务的 cancel 和基于原任务过期终态的 `EXPIRED` skip；不实现 `VOID_UNISSUED`、通用序号缺口恢复或独立 skip 槽。阶段 2 仍需完成独立可信时间、序号缺口、重启恢复、租约过期、真实 Helper socket/service 和授权安全验证；不能将用户对开发基线的批准表述为生产授权。
