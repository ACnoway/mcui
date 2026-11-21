# 架构与安全决议（阶段 0）

> 状态：架构与安全边界的工程基线已记录，仍待项目负责人及安全负责人批准；本文不是实现、测试或安全审计证明。阶段 0/1 的代码与测试状态见[实施状态记录](./phase-0-1-implementation.md)。阶段顺序和退出门槛以[分阶段流程](./phased-development-workflow.md)为准；本文件整合[项目大纲](./project-overview-and-development-workflow.md)与[Agent 草案](./agent-technical-design-v1.0.md)。安全假设见[威胁模型](./threat-model.md)，操作和审批见[权限矩阵](./panel-authz.md)。

## 1. 范围与部署

首个运行验收目标为 Debian 13.7 amd64/systemd `257.13-1~deb13u1`，Linux arm64 验证构建。V1 主控通过一键脚本或 Compose 安装，由一个管理员管理节点与 Core。本机访问为部署默认值，HTTPS 可由用户反代或由主控直接提供。SQLite 作为单机数据库，高频读写使用索引和定向事务。[V1 部署目标](./project-overview-and-development-workflow.md#13-主控安装与首次登录) · [兼容矩阵](./core-compatibility.md)

```text
浏览器 --HTTPS--> Master Web/API --受限接口--> 独立任务签发者
                        | SQLite / 受限审计、备份
Agent --出站 HTTPS Pull + 节点 Token--> Master    离线发布密钥 --> 签名制品清单
  |--受限 Unix socket--> 特权 Helper --> 固定目录与固定 systemd 单元
  |--低权限适配器/状态--> Xray | sing-box | mita（各自独立用户）
客户端 ----------------------------> Core 数据面（不经 Master）
```

Master 为集中控制面。Agent 以低权限运行并主动出站连接，首次安装包含 Agent 和辅助组件。Helper 仅具备固定动作所需的特权，各 Core 使用独立低权限身份。V1 每个节点每种 Core 最多一个受控实例。现有运行时已包含状态任务、可选 Xray 生命周期和 Agent/Helper 成对更新。[阶段 3 状态](./phase-3-progress.md)

## 2. 边界和约束

1. 浏览器/API：按操作和对象实施服务端授权，校验会话、CSRF 和请求来源，对浏览器输入和节点上报做安全处理。默认入口使用同一管理员。反代仅信任显式配置的代理连接和外部 HTTPS 地址，Cookie 按外部连接设置。[权限规则](./panel-authz.md#v1-单管理员)
2. Master/签发者：Web 进程与任务签发、发布密钥隔离。V1 由受限后台签发服务核验不可变请求、允许的操作、目标、摘要、时限和重放约束，签发前记录授权依据。当前状态签发器和 Xray 手工签发工具分别保留其实现边界。
3. Master/Agent：主控先建节点，再生成带一次性安装码的 Agent 安装命令。Agent 用系统 CA 或显式配置的私有 CA 校验 Master 的 HTTPS 服务端证书，安装码换取绑定该节点的 Token。Master 逐请求检查 Token、节点状态与资源归属。部署与旧节点迁移见[阶段 1 运维手册](./phase-1-operations.md)。轮换、撤销及迁移规则见[Agent 协议](./agent-protocol.md#2-节点接入token-轮换和撤销)。
4. Agent/Helper：使用受限本机 socket 和对端凭据，Helper 独立核验签名、目标、固定 Core 映射、租约和有效期，使用 root 私有账本防重放。状态查询与显式启用的 Xray 生命周期使用固定路径、来源和 systemd 单元。特权调用仅接受预定义的操作和参数。
5. Agent/Core：各 Core 独立用户、配置与状态；不能读取 Agent 凭据、Helper socket 或其他 Core 敏感文件。低端口能力按需最小授予；systemd 限制及实际可用性须逐平台验证。
6. 发布/配置：独立签名元数据绑定平台、版本与制品摘要；下载、解包、受限预检、健康确认与 LKG 恢复均不可省略。签名配置不等于安全配置：Master 与 Agent 双重按 Core、锁定版本和节点策略检查，未知字段默认拒绝；手动回滚产生新 revision。

## 3. 故障与数据语义

主控离线时已运行 Core 默认继续使用 LKG。Token 撤销后，主控拒绝该凭据的后续请求。持久化事务先于副作用，重启先对账；恢复失败标记 `ROLLBACK_FAILED` 或 `NEEDS_RECONCILIATION`，停止危险自动重试并告警。无法证明备份中序号、撤销状态及防回退状态新鲜时暂停签发并人工恢复。统计不可靠或未验证的版本标 `UNSUPPORTED`，不以零代替未知、不启用依赖精确计数的额度；跨节点额度仅近实时。

## 4. 人工审批与待验证清单

- **阻断阶段 0 退出**：协议规范与跨实现签名向量、任务序号缺口/取消/租约和恢复、安装引导与 Token 轮换/撤销/灾备、Helper 固定动作与默认拒绝策略须由交付文件明确并检查；逐版本配置字段在各 Core 接入前验证，不阻断阶段 0 退出。
- **制品发布。** 阶段 3 的 Xray 安装使用 GitHub Releases 和单 Ed25519 签名清单。当前部署由节点管理员预置公钥，V1 首次接入由可信安装器自动配置。首份生产发布和节点部署待验收。[制品信任方案](./artifact-trust.md)
- **运行时更新**。节点 root 监督器可主动从 Master 领取 Agent/Helper 成对更新，独立验证发布签名和节点授权后试运行。生产远程更新在部署和故障恢复验收完成前保持关闭。[成对更新](./phase-3-runtime-update.md)
- **待验证**：锁定系统版本、三种 Core 制品来源、构建和许可证，验证沙箱、健康检查、配置与统计（尤其 mita 内部状态恢复）。
- **发布门槛**：阶段 0 文档评审通过不等同实现合规；完整 V1 需阶段 0–7 和两份草案的联合验收通过、无未解决 P0 安全缺陷。
