# 架构与安全决议（阶段 0）

> 状态：架构与安全边界的工程基线已记录，仍待项目负责人及安全负责人批准；本文不是实现、测试或安全审计证明。阶段 0/1 的代码与测试状态见[实施状态记录](./phase-0-1-implementation.md)。阶段顺序和退出门槛以[分阶段流程](./phased-development-workflow.md)为准；本文件整合[项目大纲](./project-overview-and-development-workflow.md)与[Agent 草案](./agent-technical-design-v1.0.md)。安全假设见[威胁模型](./threat-model.md)，操作和审批见[权限矩阵](./panel-authz.md)。

## 1. 范围与部署

首个验收目标为 Debian 13.7/systemd `257.13-1~deb13u1` amd64/arm64；三个 Core 首批测试候选版本见[兼容矩阵](./core-compatibility.md)。目标组合尚未逐架构实测，不构成已支持声明。完整 V1 包含三种 Core 生命周期、配置与用户、可用统计及订阅；P0 先行并非完整 V1。阶段 2 仅开放带 Master 租约检查点的 `core.status` 只读查询，以及 pending cancel / expired skip 控制；没有节点副作用操作。通用缺口恢复、独立可信时间、恢复和安全验收仍未完成。

```text
浏览器 --HTTPS--> Master Web/API --受限接口--> 独立任务签发者
                        | SQLite / 受限审计、备份
Agent --出站 HTTPS Pull + 节点 Token--> Master    离线发布根 --> 可信制品元数据
  |--受限 Unix socket--> 特权 Helper --> 固定目录与固定 systemd 单元
  |--低权限适配器/状态--> Xray | sing-box | mita（各自独立用户）
客户端 ----------------------------> Core 数据面（不经 Master）
```

Master 为集中控制面；Agent 非 root、不提供公网管理端口，初始安装不包含 Core。Helper 拥有完成固定动作所需特权，Core 各自非 root 且隔离；V1 每节点每 Core 类型最多一个受控实例。SQLite 单机事务和 Go 主控/Agent、Vue 界面为设计选型，不意味着任何组件已实现或部署。

## 2. 边界和约束

1. 浏览器/API：所有请求先认证、再按操作及对象授权；页面隐藏不是授权。浏览器输入、节点上报均不可信；会话、CSRF、输出编码和审计按权限文档实施。当前状态查询由 Master 按 `security_admin`/`operator`、节点范围和固定操作授权；`auditor` 只读任务记录。
2. Master/签发者：Web 进程不直接读取任务签名密钥或发布根私钥。当前 signer 进程仅核验 V2 结构、key ID 与 `core.status` 签名范围；Master 在签名前校验操作者权限、目标和参数，并先记录授权审计。没有独立审批流程，因为只读查询不单独审批。未来高危任务须由签发服务重新核验当前权限、不可变请求、独立审批、目标与摘要，原子消费审批后签发；签名密钥、发布根和节点凭据分离。
3. Master/Agent：主控先建节点，再生成带一次性安装码的 Agent 安装命令。Agent 用系统 CA 或显式配置的私有 CA 校验 Master 的 HTTPS 服务端证书，安装码换取绑定该节点的 Token。Master 逐请求检查 Token、节点状态与资源归属。部署与旧节点迁移见[阶段 1 运维手册](./phase-1-operations.md)。轮换、撤销及迁移规则见[Agent 协议](./agent-protocol.md#2-节点接入token-轮换和撤销)。
4. Agent/Helper：本机 socket 权限和对端凭据不是授权本身；Helper 独立验证签名、目标、操作、固定 Core 映射、租约检查点和有效期，并用 root 私有账本防止重复状态查询。当前只执行固定 `/usr/bin/systemctl show` 查询；不得接受任意 shell、脚本、可执行文件、URL、路径或 unit。后续特权动作须在对应门槛通过后另行设计。
5. Agent/Core：各 Core 独立用户、配置与状态；不能读取 Agent 凭据、Helper socket 或其他 Core 敏感文件。低端口能力按需最小授予；systemd 限制及实际可用性须逐平台验证。
6. 发布/配置：独立签名元数据绑定平台、版本与制品摘要；下载、解包、受限预检、健康确认与 LKG 恢复均不可省略。签名配置不等于安全配置：Master 与 Agent 双重按 Core、锁定版本和节点策略检查，未知字段默认拒绝；手动回滚产生新 revision。

## 3. 故障与数据语义

主控离线时已运行 Core 默认继续使用 LKG。Token 撤销后，主控拒绝该凭据的后续请求。持久化事务先于副作用，重启先对账；恢复失败标记 `ROLLBACK_FAILED` 或 `NEEDS_RECONCILIATION`，停止危险自动重试并告警。无法证明备份中序号、撤销状态及防回退状态新鲜时暂停签发并人工恢复。统计不可靠或未验证的版本标 `UNSUPPORTED`，不以零代替未知、不启用依赖精确计数的额度；跨节点额度仅近实时。

## 4. 人工审批与待验证清单

- **阻断阶段 0 退出**：协议规范与跨实现签名向量、任务序号缺口/取消/租约和恢复、安装引导与 Token 轮换/撤销/灾备、Helper 固定动作与默认拒绝策略须由交付文件明确并检查；逐版本配置字段在各 Core 接入前验证，不阻断阶段 0 退出。
- **人工决议**：制品信任提案选择 TUF，仍需批准并验证具体实现、发布根保管人、阈值、轮换和离线过期、降级授权；不得将此提案视为已经部署或验证。
- **待验证**：锁定系统版本、三种 Core 制品来源/构建和许可证；验证沙箱、健康检查、配置与统计（尤其 mita 内部状态恢复）；Agent/Helper 自更新监督、断电回滚和本地恢复演练通过前禁用远程更新。
- **发布门槛**：阶段 0 文档评审通过不等同实现合规；完整 V1 需阶段 0–7 和两份草案的联合验收通过、无未解决 P0 安全缺陷。
