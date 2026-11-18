# 阶段 3 进度与未完成项

**状态：阶段 3 工程进行中，已实现 Xray 的节点本地生命周期。** 阶段 2 的正式退出门槛仍未完成。[阶段 2 进度](./phase-2-progress.md)

## Xray 节点本地生命周期

- Linux amd64/arm64 的 `mcui-xray` 由本地 root 执行。支持安装、启停、升级、单独命令显式降级、卸载、状态和对账恢复。制品操作要求输入精确的三段数字版本和 SHA-256，核对本机架构、审核状态和 TUF 当前 target。启停和卸载要求匹配已提交的版本和摘要。
- 下载使用固定上游地址。安装器用同一安全打开的文件描述符复验 ZIP 长度和散列，限制目录大小、条数和展开大小，只提取 `xray`、`geoip.dat` 和 `geosite.dat`，并验证 ELF 机器类型。它生成固定的空 JSON 引导配置，归档内配置和安装钩子均会被拒绝。
- 根目录与内容寻址的版本目录由 root 管理。运行文件固定为 `0444` 或 `0555`，每次激活或恢复重验文件散列。候选预检和服务分别使用固定 systemd unit、动态低权限身份、无外网沙箱和资源上限。健康确认连续观察 systemd 的运行状态与主 PID 两秒。引导配置供生命周期验证。
- 事务事前持久化意图，原子切换版本指针，再确认启动或停止结果。失败恢复已提交的二进制、配置和运行状态。失败恢复保留未决状态并报 `ROLLBACK_FAILED`。开机一次性 unit 以最后提交状态对账。卸载清理受控版本目录，保留事务状态和 TUF 私有缓存。
- Master、Agent、Helper 的远程任务仍为只读状态查询。面板状态也继续查询阶段 2 的 unit 映射。本地部署和故障恢复见[阶段 3 操作说明](./phase-3-operations.md)。

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
- GitHub API digest 是主控缓存校验依据。该缓存的制品仍需独立 TUF 授权。精确版本、架构、文件和摘要全部匹配的备用下载路径待接入。

## 已实现的 TUF 客户端基础

- `internal/artifacttrust` 固定使用官方 `github.com/theupdateframework/go-tuf/v2 v2.4.2`。每次查找以离线配置的 root 为信任起点，刷新 root/timestamp/snapshot/targets 与按需委派 targets；缓存目录分离、校验 `0700` 且拒绝符号链接。初始 root 不从网络下载。
- 客户端记录已通过旧根和新根阈值验证的 root，即使后续元数据刷新失败也保留。后续从离线引导 root 起逐个验证以 `0400` 原子追加保存的轮换链。独立于节点本地状态的单调检查点仍待实现。
- target 路径固定为 `cores/{core}/{version}/linux/{本机架构}/{官方文件名}`；只接受 Xray、sing-box、mita 的固定资产映射。自定义元数据严格绑定由 SHA-256 派生的制品 ID、Core、版本、OS/架构、`upstream-prebuilt`、固定归档格式、source ID、审核记录 ID 和明确的上游签名状态。拒绝重复或未知字段、错误绑定、缺少 SHA-256 和超过 512 MiB 的 target。
- 下载仅访问固定 GitHub Release asset URL，最多 5 次跳转到允许的 GitHub 官方资产/CDN 主机，禁用代理并拒绝非公网 DNS 地址。下载字节按 TUF length 与 SHA-256 重新校验，成功后才以摘要名、`0400` 权限原子发布到私有缓存；错误字节和中断下载不会留下可用缓存文件。
- 本地工具依赖 TUF 审核记录所提供的 `review_id` 和上游签名事实状态，并拒绝 `unverified`。审核记录存储、上游签名独立核验、发布仓库、生产密钥、Agent/Helper 与任务路径尚待接通。

## 后续工作

1. 已实现 `mcui-tuf` 准备、逐人签署、核验和组装发布目录，Xray 工具要求独立的 Core 委派。待任命实际保管人、核对离线信任根指纹、完成上游制品审核并部署 HTTPS 仓库。[发布手册](./phase-3-release.md)
2. 将客户端安全接入 Agent 固定下载路径，绑定签名任务中的制品 ID、精确版本、架构和摘要；实现 Helper 独立重验、精确匹配备用缓存回退条件和归档安全解包。
3. 建立高危操作 MFA 复验、独立审批和签发者的可信授权来源，接通签名生命周期任务及 Helper 固定操作，面板展示任务实际结果。
4. 在故障注入环境验证本地事务的磁盘写满、断电、启动失败及恢复失败路径，并核对官方制品与固定 unit 的兼容性。
5. Agent/Helper 同源双架构制品已可打包，TUF 发布端可使用独立的 `runtime-targets` 审核和签署候选包。本地人工修复已有手册。独立更新任务授权、启动监督和自动恢复待实现。
6. 在 `ro` 的隔离 Debian 13.7 amd64 环境测试制品拒绝、下载中断、磁盘不足、错误架构、恶意归档、启动失败和恢复。Linux arm64 验证构建，按证据更新能力矩阵。

## 当前验证边界

目录和备用缓存测试覆盖固定源、分页、下载校验和缓存发布。TUF 测试覆盖阈值签名、root 轮换和目标撤销。Debian amd64 已在隔离的 systemd 环境验证官方 Xray 本地生命周期、磁盘写满和事务进程被强制终止后的恢复。该次验证使用测试 TUF 根和本机 TLS 仓库，主机断电、生产 NTS、生产密钥治理和远程端到端下发仍待验证。Linux arm64 仅验证构建。[分阶段开发流程](./phased-development-workflow.md) · [能力矩阵](./core-compatibility.md)

## 已执行检查

| 检查 | 结果 | 环境/范围 |
|---|---|---|
| Agent/Helper 发布包、TUF 轮换与竞态检测 | 通过，提交 `6ea294b`（2026-11-18） | `ro:/root/mcui` 完整 `scripts/check-static.sh`、`go test -race -count=1 ./cmd/mcui-tuf ./internal/artifacttrust ./internal/xrayruntime` 和 `scripts/build-runtime-release.sh` 通过。测试验证新旧 root 阈值、更新角色签署、两架构 ZIP 成员、ELF 机器类型及 SHA-256；arm64 仅构建和检查制品 |
| TUF 发布工具与完整仓库检查 | 通过，提交 `acff3db`（2026-11-18） | `ssh ro` 的 `/root/mcui`。测试覆盖 Core 签名不足、首版组装、撤销和版本复用拒绝。全量 Go vet/build/test、amd64/arm64 交叉构建、Web 生产构建通过 |
| 真实 Xray amd64 本地生命周期与故障注入 | 通过，提交 `acff3db`（2026-11-18） | `ro` 的 Debian 13.7、systemd `257.13-1~deb13u1`，临时 unit、临时 TLS metadata 和测试签名。官方 `v26.10.31` 和 `v26.11.9` ZIP 经 GitHub API 与附带 `.dgst` 校验，实际运行于隔离低权限服务。验证未批准目标、截断下载、安装、升级、显式降级、启停、卸载、撤销、真实 tmpfs 写满和切指针后 `SIGKILL` 恢复。测试副本使用隔离路径、loopback metadata 与测试时钟，制品从固定官方 URL 下载。临时资源已清理。[v26.10.31](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31) · [v26.11.9](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9) |
| `bash scripts/check-static.sh` | 通过，提交 `f48ced9`（2026-11-18） | `ssh ro`，`/root/mcui`，Debian 13.7 amd64；Go 1.27.4、Node.js 26.13.1、pnpm 12.17.0。Go 格式/vet/build/test、Linux amd64/arm64 交叉构建、协议向量和冻结 Web 生产构建均通过 |
| `go test -race -count=1 ./internal/artifacttrust ./internal/xrayruntime` | 通过，提交 `f48ced9` | 同一远程环境。阈值不足、轮换保留、目标撤销、归档拒绝和事务恢复测试均通过 |
| Xray systemd unit 校验及生命周期冒烟测试 | 通过，提交 `f48ced9` | Debian 13.7 amd64、systemd `257.13-1~deb13u1`。临时 unit 和合成可执行制品验证隔离身份、只读运行目录、预检、健康确认、启动失败回滚、启停、卸载和恢复入口。测试后清理临时 unit，未启用系统服务 |
| 官方 Xray `v26.10.31` amd64 ZIP | 通过文件检查，提交 `f48ced9` | GitHub Release API SHA-256 `e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214` 与下载字节一致；通过 ZIP 白名单解包和 ELF 架构检查。该样本未运行，未使用生产 TUF 授权。[官方发布页](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31) |
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
| 通过 Agent 下发安装、amd64 故障恢复 | 未执行 | 远程签发和 Helper 生命周期授权尚未接入 |
