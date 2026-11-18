# 阶段 0/1 实施状态

> 更新日期：2026-11-16。本文为阶段 0/1 历史记录，不代替项目负责人签核、项目内安全检查或生产授权。阶段 0/1 的仓库内工程范围已完成；正式退出门槛仍待责任人执行。阶段 2 后续状态见 [V2 开发基线](./phase-2-protocol-draft.md)和仓库 README。

## 阶段 0：设计冻结与项目基线

| 范围 | 工程结果 | 正式退出门槛 |
|---|---|---|
| 架构、威胁与支持范围 | 架构、威胁模型、授权、协议、发布信任、配置策略和 Core 兼容基线已记录。固定 Debian 13.7 amd64/systemd 257.13-1~deb13u1 为运行验收目标，锁定三种 Core 的首轮候选版本/官方来源。 | 项目负责人确认阶段 0 的风险及范围。身份通道在 Debian amd64 隔离环境运行验收，Linux arm64 验证构建。Xray 制品在阶段 3 核验，其他 Core 在阶段 6 分别核验。 |
| 身份与签名协议 | V1 task/config/cancel/skip schema、严格 JSON、JCS、Ed25519 域分离、序号槽、取消/skip 竞争、租约、ACK、恢复、审批和密钥用途语义已冻结为设计基线。Go 实现 schema/验签；共享向量含 4 个正例和 9 个反例，由 Go 与独立 Node.js 校验。尚未接入任务运行时。 | 项目内检查协议、向量和状态恢复边界；负责人批准审批人与密钥责任。 |
| 信任与发布 | 选择 TUF 作为发布元数据基线，记录离线阈值、过期、回滚、根轮换和恢复要求；配置策略默认拒绝，Helper 操作限定为固定白名单设计。 | TUF 客户端/元数据/签名密钥及保管人、上游制品来源审查、Helper 参数绑定与 Core 版本策略仍未实现或批准。 |
| 仓库与静态基线 | 固定 Go 1.27.4、Node.js 26.13.1 LTS、pnpm 12.17.0（2026-11-16 当前补丁基线）；新增静态检查脚本、`.nvmrc`、SHA 固定 action 的只读 GitHub Actions workflow。脚本覆盖格式、vet、build/test、Linux amd64/arm64 交叉构建、协议向量及前端冻结安装/构建。 | 目标提交的远端检查结果和仓库规则是否生效仍须核验；默认开发流程允许直接在 `master` 开发，不强制 PR 或非作者审批。漏洞扫描、许可证门禁、SBOM、fuzz/race 等未纳入本轮基线。 |

**工程交付完成；阶段 0 正式签核未完成。** 尚需项目内安全检查、密钥/审批责任落实和阶段 0 范围内的决议证据；各 Core 的实测及制品核验在各自接入阶段进行。没有这些证据不能标记受支持平台或发布获准。

## 阶段 1：Master 与空 Agent

| 范围 | 工程结果 | 验证与剩余门槛 |
|---|---|---|
| 存储与恢复候选 | SQLite 实体表及 schema migration 保留；新增一致性快照、结构与完整性检查、仅新路径的恢复候选 CLI。备份设为所有者可读写且不会覆盖目标。 | Store round-trip、损坏库拒绝和禁止覆盖测试通过。备份加密、独立不可变检查点、保留/新鲜度核验与真实恢复演练未完成。 |
| 管理员会话与授权 | TOTP、可撤销会话、15 分钟空闲/8 小时绝对超时、10 分钟敏感操作 MFA 复验、CSRF/来源检查和限流已实现。面板允许 security_admin 创建范围受限 auditor/operator；服务端校验子集，禁用时撤销其全部会话。 | 管理员范围、CSRF、MFA、创建和会话撤销集成测试通过。全局 security_admin 的带外恢复、角色变更、双人首信任仪式未实现。 |
| 节点与 Agent | TLS 1.3、一次性邀请、CSR 持有证明、Agent mTLS 心跳、幂等轮换、禁用与证书撤销实现；节点和审计读取按角色/范围过滤。Agent 不包含 Core，也没有任务投递/执行接口。 | 现有 Go 集成测试覆盖注册、撤销、轮换、越权和会话边界。在线 Node CA 密钥生产托管、干净机安装和故障恢复仍待核验。 |
| 运维交付 | 添加 panel/agent 最小权限 systemd units、Debian 部署及账号/备份/恢复候选手册。 | 远端静态构建及单元语法检查通过后，在 Debian 13.7 amd64 隔离环境演练安装、沙箱、日志脱敏、备份与恢复。生产备份加密和不可变检查点另行实施。 |
| 阶段边界（2026-11-16 历史状态） | 当时没有任务轮询、Helper、Core 安装、配置变更、Core 管理或统计 API；`core.status` 仅为签名 schema/测试向量。 | 后续状态以 [V2 开发基线](./phase-2-protocol-draft.md)和仓库 README 为准。 |

**阶段 1 仓库内工程范围完成；正式退出仍待干净 VM 验收、项目内安全及日志检查及密钥和灾备责任人签核。** 自动化测试不等于生产验收。

## 验证记录

仓库检查入口为 [`scripts/check-static.sh`](../scripts/check-static.sh)。该脚本检查 Go 格式、vet、build/test、Linux 双架构交叉构建、协议向量、pnpm 冻结安装和 Vue 构建；CI workflow 已提交。自动检查不能替代真实 Debian VM、systemd 行为、arm64 运行、项目内安全检查或灾备演练。

| 日期 / 提交 | 环境 | 检查 | 结果 |
|---|---|---|---|
| `0f7ca50` / 2026-11-16 | 本地 Windows，Go 1.26.4，Node 24.22.1，pnpm 11.25.0 | `gofmt -l cmd internal`、`go vet ./...`、`go test ./...`、`go build ./...`、协议向量 | 历史记录：当时格式/分析/构建/测试通过；4 正例、8 反例通过。该环境版本不符合当前锁定工具链，且未执行前端构建。 |
| `bf49200` / 2026-11-16 | SSH `ro` 的 `/root/mcui`，Linux amd64，Go 1.24.4、Node 26.12.1、pnpm 12.15.0 | `bash scripts/check-static.sh` | 历史记录：完整静态脚本通过，含冻结依赖安装和前端生产构建；未包含 Debian 干净 VM、systemd 行为/arm64 实机、项目内安全检查或灾备演练。 |
| `9283224` / 2026-11-16 | SSH `ro` 的 `/root/mcui`，Linux 6.12.107 amd64、systemd 257.13-1~deb13u1、Go 1.27.4、Node 26.13.1、npm 11.20.0、pnpm 12.17.0 | `bash scripts/check-static.sh`；`systemd-analyze verify` | 通过：Go 格式/vet/build/test、Linux amd64/arm64 交叉构建、4 正例/9 反例向量、冻结 pnpm 安装、Vue 类型检查和 Vite 构建。两个 unit 使用临时 alternate root 与实际编译的 panel/agent 可执行文件校验通过；未安装或启动服务。 |

历史远端结果涵盖 Linux amd64 主机上的交叉构建和 unit 语法与装载校验。阶段 0/1 的 Debian 13.7 amd64 安装和 systemd 沙箱验收仍待执行。阶段 2 运行时见[阶段 2 进度](./phase-2-progress.md)。
