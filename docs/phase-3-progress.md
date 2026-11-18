# 阶段 3 进度与未完成项

**状态：阶段 3 初始工程工作进行中；已有只读官方版本目录和主控备用制品缓存，尚无 Core 安装或生命周期操作。** 阶段 2 的正式退出门槛仍未完成，状态见[阶段 2 进度](./phase-2-progress.md)。本阶段的任何构建结果都不代表 Core 制品已获批准或可用于生产安装。

## 已实现的只读版本目录

- Master 为已登录管理员提供 `GET /api/v1/admin/cores/releases?page=N`，从三个固定 GitHub 官方仓库读取 Xray、sing-box 和 mita 的最近发布版本、发布页及制品链接；每页 10 个，最多浏览最近 100 个，避免一次取回大型资产清单。
- 上游请求使用固定 API 地址、8 秒超时、8 MiB 单响应上限和不跟随重定向的 HTTP 客户端。返回的发布页与制品链接必须匹配对应官方仓库、版本和文件名；不匹配的记录不进入面板。
- Master 进程内缓存目录 10 分钟；上游暂时不可用时，最多返回 24 小时内的最近成功快照并标记为过期。缓存不会跨 Master 重启保留。
- 面板展示版本、预发布标记、发布时间、官方发布页、制品文件名、大小和 GitHub Release API 提供的 SHA-256 digest（若有）。
- 此目录仅用于版本发现。目录条目不会自动转成任务 URL，也不构成安装授权。

## 已实现的主控备用制品缓存

- `mcui-panel -core-backup-dir` 指定持久化目录，默认 `./data/core-backups`；systemd unit 使用 `/var/lib/mcui/core-backups`，位于 `StateDirectory=mcui` 管理的可写路径。主控启动后后台同步部署时的官方最新版；同步最多运行 45 分钟，不阻塞 HTTP 服务。
- 每种 Core 选择官方目录中最新的非预发布版本，只缓存固定映射的 Linux amd64、arm64 两个资产。若缺少任一架构的资产、API 未提供有效 SHA-256 digest，或大小超出 512 MiB，则该 Core 本次不更新。
- 下载固定 GitHub release URL，最多允许 5 次 HTTPS 跳转至 GitHub 官方资产 CDN；下载流限制为目录公布大小，并校验完整字节数及 API digest。制品按摘要放入 `blobs/`，manifest 原子替换并记录 Core、仓库、精确版本、架构、文件名、源 URL、长度、摘要、存储键和缓存时间。
- 每种 Core 单独发布：该 Core 的两个架构均下载并验证成功后才替换其 manifest 记录；失败时保留该 Core 原有版本。成功替换后清理不再被 manifest 引用的旧 blob，因此每个 Core 只保留一版；不同 Core 可分别成功或失败。
- 已登录管理员可通过 `GET /api/v1/admin/cores/backups` 查看 manifest，面板显示版本、架构、文件大小、digest 和更新时间。目录权限收紧为仅服务账号可访问，manifest 不可被非普通文件或未知字段绕过。
- GitHub API digest 只代表上游声明并由主控重新计算验证，尚未经过本项目 TUF targets 阈值签署；缓存仅为未来精确匹配的备用副本，不授权安装。未来常规安装仍由 Agent 直连官方源；备用仅允许精确版本、架构、文件和摘要全部匹配，不能静默改装其他版本。当前尚无安装任务、Agent 下载路径、Helper 解包/安装事务或 Core 服务管理操作。

## 已实现的 TUF 客户端基础

- `internal/artifacttrust` 固定使用官方 `github.com/theupdateframework/go-tuf/v2 v2.4.2`。每次查找以离线配置的 root 为信任起点，刷新 root/timestamp/snapshot/targets 与按需委派 targets；缓存目录分离、校验 `0700` 且拒绝符号链接。初始 root 不从网络下载。
- 客户端记录每次成功刷新获得的版本化 root，并在后续创建 updater 前，从离线引导 root 起逐个验证 root 轮换链。root 文件以 `0400` 原子追加保存。该检查阻止客户端初始化时把已记录 root 链降回旧版本，但记录与元数据仍位于同一节点回滚域；没有独立单调检查点，也没有双库/灾备回滚检测。
- target 路径固定为 `cores/{core}/{version}/linux/{本机架构}/{官方文件名}`；只接受 Xray、sing-box、mita 的固定资产映射。自定义元数据严格绑定由 SHA-256 派生的制品 ID、Core、版本、OS/架构、`upstream-prebuilt`、固定归档格式、source ID、审核记录 ID 和明确的上游签名状态。拒绝重复或未知字段、错误绑定、缺少 SHA-256 和超过 512 MiB 的 target。
- 下载仅访问固定 GitHub Release asset URL，最多 5 次跳转到允许的 GitHub 官方资产/CDN 主机，禁用代理并拒绝非公网 DNS 地址。下载字节按 TUF length 与 SHA-256 重新校验，成功后才以摘要名、`0400` 权限原子发布到私有缓存；错误字节和中断下载不会留下可用缓存文件。
- 此客户端目前是隔离的基础组件，未被 Agent/Helper 或任务路径调用。`review_id` 和上游签名状态须由已签 TUF metadata 提供；代码不验证该 ID 对应的审计数据库记录，也不独立验证上游签名。没有发布仓库、生产 root/targets 密钥、批准的 target metadata、任务审批/MFA、Helper 二次验证、归档安全解包、安装事务、Core unit/LKG 或 Agent/Helper 自更新。

## 后续工作

1. 建立角色分离的 TUF 发布仓库、2-of-3 root/targets 密钥保管和审核记录流程，生成离线信任根并在独立工具/规范互操作测试中验证轮换、threshold 与撤销；当前代码没有生产 key material 或 repository。
2. 将客户端安全接入 Agent 固定下载路径，绑定签名任务中的制品 ID、精确版本、架构和摘要；实现 Helper 独立重验、精确匹配备用缓存回退条件和归档安全解包。
3. 建立高危操作 MFA 复验和独立审批后，增加签名安装/升级/显式降级/卸载任务及 Helper 固定操作。
4. 为 Xray 增加不可变版本目录、固定 systemd unit、独立低权限账号、健康确认、LKG 恢复和启动对账。
5. 实现 Agent/Helper 独立授权更新、旧版本监督、自动恢复和本地人工修复；完成失败恢复演练前保持远程自身更新关闭。
6. 在 Debian 13.7 amd64/arm64 分别测试制品拒绝、下载中断、磁盘不足、错误架构、恶意归档、启动失败和恢复；按证据更新能力矩阵。

## 当前验证边界

目录和备用缓存测试覆盖固定源解析、分页、上游 URL 校验、版本选择、存储 manifest、下载长度/摘要、跳转主机、缓存原子替换和失败保留。TUF 客户端单元测试覆盖 target metadata 绑定、重复/未知字段、SHA-256/长度、固定源与跳转、私有缓存权限和非公网地址拒绝；还未覆盖生产 TUF repository/密钥轮换互操作、上游签名事实、安装、Helper 或节点故障恢复。阶段 3 退出门槛见[分阶段开发流程](./phased-development-workflow.md)；任何 Core 在兼容矩阵实测前仍是未验证状态。

## 已执行检查

| 检查 | 结果 | 环境/范围 |
|---|---|---|
| `bash scripts/check-static.sh` | 通过，提交 `1b7ca21`（2026-11-18），退出码 0 | `ssh ro`，`/root/mcui`，Debian 13 amd64；Go 1.27.4、Node.js 26.13.1、pnpm 12.17.0。包括新增 TUF/corecatalog 测试、Go 全量 vet/build/test、amd64/arm64 交叉构建、V1/V2 向量、冻结 Web 安装及 Vue 类型/生产构建 |
| TUF 客户端与 Core 固定源定向测试 | 通过，提交 `1b7ca21` | `go test ./internal/artifacttrust ./internal/corecatalog`；目标绑定、缓存/跳转/IP 拒绝正反例通过 |
| `bash scripts/check-static.sh` | 通过，提交 `5db70ad` | `ssh ro`，`/root/mcui`，Debian 13.7 amd64；Go 1.27.4、Node.js 26.13.1、pnpm 12.17.0 |
| Go 格式、vet、构建与全量测试 | 通过，提交 `5db70ad` | 包含备用缓存摘要/长度/跳转/更新失败测试、Master 备份 API 认证测试及全量现有测试 |
| Linux amd64/arm64 构建 | 通过，提交 `5db70ad` | 交叉构建；没有 arm64 实机或干净 VM 证据 |
| V1/V2 协议向量 | 通过，提交 `5db70ad` | 分别 4 个/9 个及 3 个/29 个正反例 |
| Web 冻结依赖与生产构建 | 通过，提交 `5db70ad` | `pnpm install --frozen-lockfile`、`pnpm build`、Vue 类型检查 |
| Master systemd unit | 通过，提交 `5db70ad` | Debian 13.7；用 `/tmp` 独立根目录和临时 panel 构建产物运行 `systemd-analyze verify`，未安装到系统服务路径 |
| 官方 API 在线 payload smoke test | 通过（2026-11-17） | 每页 10 条解压后约 1.3 MiB（Xray）、3.4 MiB（sing-box）、0.8 MiB（mita）；100 条请求为 5.6–32.1 MiB，因此采用按需分页 |
| 官方 Core 资产实际下载与摘要校验 | 通过（2026-11-17） | `ssh ro` 临时运行 `BackupStore.Sync`，实际下载并校验 6 个资产：Xray v26.11.9（30.5 MiB）、sing-box v1.14.4（59.1 MiB）、mita v3.39.0（6.8 MiB）；只写入临时目录，测试后清理 |
| Agent 安装、systemd 故障恢复 | 未执行 | 尚未连接 Agent 安装、Helper 解包/安装事务或 Core 生命周期运行时 |
