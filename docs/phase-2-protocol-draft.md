# 阶段 2 状态任务协议（开发基线）

用户于 2026-11-17 在会话中批准下述只读 V2 方案作为阶段 2 开发基线；这不构成生产上线或阶段退出批准，也不是独立安全评审记录。本文描述 `internal/protocol/v2.go` 和 `internal/protocol/testdata/protocol-v2.json` 中的互操作协议，不修改或替代已冻结的 V1 基线。Admin 状态任务 API、隔离 signer、Agent mTLS 投递/ACK、pending cancel、expired skip、受限序号恢复、NTS 时间校验、启动时任务/审计对账和 Helper 固定只读执行已有运行时实现；本次远程构建验证结果及正式阶段退出状态记录于[阶段 2 进度](./phase-2-progress.md)。

## 提议的状态任务

- 域为 ASCII `MCUI-TASK-V2` 后接一个换行字节；其余编码遵循 V1 的严格 JSON、JCS 和 Ed25519 基线。V1/V2 域不同，签名不可互换。
- 严格只允许 `schema_version: 2` 和 `operation: core.status`。通用字段及节点内连续序号、时间上限沿用 V1 约束；`payload` 唯一字段 `core` 为 `xray`、`sing-box` 或 `mita`。
- `step` 仅有 `step_id`、`parameters`、`artifact_sha256`、`architecture`、`expected_state`。唯一允许的步骤 ID 为 `core.status`；`parameters` 只包含 `core` 且须等于 `payload.core`。
- **已批准的只读语义**：只读状态查询不涉及制品或架构，这两个字段使用字面值 `not-applicable`，它不是有效摘要或架构，也不授权制品；`expected_state` 固定为 `observe`，不授权改变状态。这仅适用于本次批准的状态查询，不是对后续安装、升级或配置操作的通用设计。
- 无额外字段；不允许请求提供 shell、路径、URL、unit、脚本或 argv。当前 Helper 将签名 Core 精确映射到 `xray.service`、`sing-box.service` 或 `mita.service`，并只调用固定的 `systemctl show` 属性集合。该实现仍需真实 Linux/service 沙箱和越权测试。

## 草案不提供的安全保证

`VerifyV2Task` 仅检查草案结构和调用方传入的公钥对应的签名。它不选择或验证受信密钥及用途，不检查本机身份、当前可信时间、序号、审批、撤销、对端凭据或持久化重放账本，也不执行任何动作。签名正确不等于具有执行授权。

现有角色文档对高危任务发起人的要求仍见[权限基线](./panel-authz.md)与本文件第 5.2 节。**本阶段已决定：只读 `core.status` 查询不单独审批**；Master 实现逐请求验证 `security_admin`/`operator` 身份、节点对象范围及只读操作权限并写授权审计。此决定不适用于后续高危任务。Master、Agent 和 Helper 已通过 chrony 检查 `time.cloudflare.com` 的 NTS 认证、样本新鲜度和 tracking 误差；部署前必须按[操作说明](./phase-2-operations.md)配置 chrony。主控可配置独立检查点检测两库同时回滚；生产密钥保管、完整灾难恢复和跨数据库原子事务仍待落实。

## 验证与待办

共享向量使用公开测试 seed，严禁用于生产。Go 测试和 `scripts/verify-protocol-v2-vectors.mjs` 对同一组签名向量和反例进行解析及签名校验；常规检查脚本运行两者。向量通过只能证明所测互操作情况，不等于完整规范或系统安全验收通过。V1 cancel/skip 与 V2 状态任务分开签名：运行时支持未开始状态任务 cancel、基于原任务过期终态的 `EXPIRED` skip、已签发未投递槽的 `VOID_UNISSUED`，以及可证明过期终态历史槽的序号补取；未知缺口和独立 `CANCELED` skip 仍失败关闭。任务库与审计库启动对账可修复单侧崩溃导致的后置审计缺失，但没有跨库原子提交或外部单调检查点。正式退出仍需真实 Helper socket/service、断电/恢复演练和项目内安全验证；不能将用户对开发基线的批准表述为生产授权。
