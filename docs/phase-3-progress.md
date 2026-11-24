# 阶段 3 进度与未完成项

第三阶段工程交付已完成。Xray 本地和远程生命周期、官方版本目录、主控备用缓存及中断对账已实现。Agent/Helper 支持从本地或 Master 发起独立授权的成对更新。单管理员可从官方稳定版本中选择目标，并由后台独立签发投递。Core 安装不再依赖签名清单；官方版本选择流程与目标节点部署仍待验收。[成对更新](./phase-3-runtime-update.md) · [面板签发与手工流程](./phase-3-approval.md) · [生产发布验收](./phase-3-release.md#生产发布验收)

## 后续工作

| 批次 | 已有交付与验证 | 剩余事项 |
|---|---|---|
| 主控与节点部署 | 主控安装包、Compose、单管理员初始化、Agent 一键接入和首次心跳已在隔离环境验证。[主控部署](./master-deployment.md#验证记录) · [节点接入](./phase-1-operations.md#节点首次接入) | 接入正式发布流程，验证 GitHub Releases 的安装入口和目标节点部署。 |
| Xray 业务连接 | 默认使用空 JSON 引导配置。首个受控 SOCKS5 入站已在 Debian amd64 通过真实客户端和回滚验收，证据归档于阶段 4。[隔离验收记录](./phase-4-xray-inbound.md#隔离验收记录) | 阶段 4 继续推进面板入站授权、统计和订阅，生产发布按本阶段手册独立验收。 |
| 低配运行 | 已接入节点 Token 索引、心跳定向更新及 Agent/Helper 成对回滚。[主控检查](./master-deployment.md#验证记录) | 记录低配主控并发结果和目标环境的备份恢复证据。 |
| 生产验收 | 已用测试信任材料完成隔离部署、签发和恢复演练。 | 在目标节点验收官方版本选择与制品摘要校验，确认 Cloudflare NTS 同步，并复验断电、磁盘写满恢复和结果回报。 |

各批次顺序见[当前开发顺序](./phased-development-workflow.md#4-当前开发顺序)。

成对更新沿用双架构 ZIP。节点监督器核对独立发布签名及绑定节点与当前版本的更新授权，验证架构后原子切换两个服务。试运行检查节点身份、账本和 Helper 握手，提交前暂停任务处理。失败或中断可恢复上一次提交的成对版本，人工修复入口只需节点本地权限。

每批用测试节点和测试信任材料完成定向验证，记录提交、命令和结果。Xray 和 Agent/Helper 的远程更新均支持单机 Master。独立检查点是可选的整库防回滚保护。目标节点的 Cloudflare NTS 和官方版本安装流程按[发布验收](./phase-3-release.md#生产发布验收)验证。阶段 2 的正式验收状态见[阶段 2 进度](./phase-2-progress.md)。

## Xray 节点本地生命周期

- Linux amd64/arm64 的 `mcui-xray` 由本地 root 执行。支持安装、启停、升级、单独命令显式降级、卸载、状态和对账恢复。制品操作使用精确的三段数字版本和 SHA-256，并核对本机架构与固定官方来源。启停和卸载要求匹配已提交的版本和摘要。
- 下载使用固定上游地址。安装器用同一安全打开的文件描述符复验 ZIP 长度和散列，限制目录大小、条数和展开大小，只提取 `xray`、`geoip.dat` 和 `geosite.dat`，并验证 ELF 机器类型。它生成固定的空 JSON 引导配置，归档内配置和安装钩子均会被拒绝。
- 根目录与内容寻址的版本目录由 root 管理。运行文件固定为 `0444` 或 `0555`，每次激活或恢复重验文件散列。候选预检和服务分别使用固定 systemd unit、动态低权限身份、无外网沙箱和资源上限。健康确认连续观察 systemd 的运行状态与主 PID 两秒。引导配置供生命周期验证。
- 事务事前持久化意图，原子切换版本指针，再确认启动或停止结果。失败恢复已提交的二进制、配置和运行状态。失败恢复保留未决状态并报 `ROLLBACK_FAILED`。开机一次性 unit 以最后提交状态对账。卸载清理受控版本目录，保留事务状态和内容寻址制品缓存。
- 节点启用阶段 3 安装配置后，可接受精确的远程 Xray 安装任务，并将 Xray 状态查询映射到 `mcui-xray.service`。单管理员从官方稳定版本中选定目标，后台按节点范围签发并投递。手工签发流程继续支持范围内运维员，旧提案和任务回报按原流程收尾。[授权与签发](./phase-3-approval.md) · [操作说明](./phase-3-operations.md)
- Agent 重启后可对账未决安装。Helper 以原签名信封摘要核对自己的账本和 Xray 事务记录。能证明提交或回滚时，Agent 原子保存结果并补报，Master 关闭当前槽位，随后可派发下一序号。待对账投递没有安装租约，原任务过期后仍能补报。缺失或冲突的证据继续阻塞当前序号。[远程安装对账](./phase-3-operations.md#远程安装对账)
- 远程启动和停止沿用节点范围、MFA、独立签发和同一节点序号，绑定实际已安装的版本、架构与 SHA-256。Helper 在当前租约下调用本地生命周期事务，只操作固定的 `mcui-xray.service`。确认启动或停止后才提交结果。中断后沿用原签名任务对账和回滚规则。[远程启停](./phase-3-operations.md#6-远程启停)
- 远程升级和显式降级同时绑定已安装版本、目标版本及摘要。候选切换失败时恢复上一个可用版本和运行意图。降级和卸载分别确认后才能投递。卸载停止服务并清理受管版本，保留任务凭证和制品缓存。[远程版本切换与卸载](./phase-3-operations.md#7-远程版本切换与卸载)

## 已实现的只读版本目录

- Master 为已登录管理员提供 `GET /api/v1/admin/cores/releases?page=N`，从三个固定 GitHub 官方仓库读取 Xray、sing-box 和 mita 的最近发布版本、发布页及制品链接；每页 10 个，最多浏览最近 100 个，避免一次取回大型资产清单。
- 上游请求使用固定 API 地址、8 秒超时、8 MiB 单响应上限和不跟随重定向的 HTTP 客户端。返回的发布页与制品链接必须匹配对应官方仓库、版本和文件名；不匹配的记录不进入面板。
- Master 进程内缓存目录 10 分钟；上游暂时不可用时，最多返回 24 小时内的最近成功快照并标记为过期。缓存不会跨 Master 重启保留。
- 面板展示版本、预发布标记、发布时间、官方发布页、制品文件名、大小和 GitHub Release API 提供的 SHA-256 digest（若有）。
- 通用目录用于版本发现；安装抽屉额外读取最多 100 个 Xray Releases，并按稳定版本和节点架构筛选。所选版本会再次经 Release API 解析，目录条目自身不作为下载 URL 或安装授权。

## 已实现的主控备用制品缓存

- `mcui-panel -core-backup-dir` 指定持久化目录，默认 `./data/core-backups`；systemd unit 使用 `/var/lib/mcui/core-backups`，位于 `StateDirectory=mcui` 管理的可写路径。主控启动后后台同步部署时的官方最新版；同步最多运行 45 分钟，不阻塞 HTTP 服务。
- 每种 Core 选择官方目录中最新的非预发布版本，只缓存固定映射的 Linux amd64、arm64 两个资产。若缺少任一架构的资产、API 未提供有效 SHA-256 digest，或大小超出 512 MiB，则该 Core 本次不更新。
- 下载固定 GitHub release URL，最多允许 5 次 HTTPS 跳转至 GitHub 官方资产 CDN；下载流限制为目录公布大小，并校验完整字节数及 API digest。制品按摘要放入 `blobs/`，缓存索引原子替换并记录 Core、仓库、精确版本、架构、文件名、源 URL、长度、摘要、存储键和缓存时间。
- 每种 Core 单独发布：该 Core 的两个架构均下载并验证成功后才替换其缓存索引记录；失败时保留该 Core 原有版本。成功替换后清理不再被索引引用的旧 blob，因此每个 Core 只保留一版；不同 Core 可分别成功或失败。
- 已登录管理员可通过 `GET /api/v1/admin/cores/backups` 查看缓存索引，面板显示版本、架构、文件大小、digest 和更新时间。目录权限收紧为仅服务账号可访问，索引不可被非普通文件或未知字段绕过。
- GitHub API digest 用于主控同步。远程 Xray 安装在官方源不可用时凭签名任务和当前租约请求备用缓存。主控只提供精确匹配的制品，Agent 和 Helper 再按已验签任务复验字节。

## 历史 Core 签名清单和 TUF 实现

早期实现包含 `mcui-manifest` 单签名清单和 TUF 元数据校验，相关代码、测试和发布记录保留用于历史验证。当前 Xray 任务直接绑定官方 Release 的精确版本、架构与摘要，不再要求清单版本或节点端 Core 发布公钥。

## 迁移前使用的 TUF 客户端

- `internal/artifacttrust` 固定使用官方 `github.com/theupdateframework/go-tuf/v2 v2.4.2`。每次查找以离线配置的 root 为信任起点，刷新 root/timestamp/snapshot/targets 与按需委派 targets；缓存目录分离、校验 `0700` 且拒绝符号链接。初始 root 不从网络下载。
- 客户端记录已通过旧根和新根阈值验证的 root，即使后续元数据刷新失败也保留。后续从离线引导 root 起逐个验证以 `0400` 原子追加保存的轮换链。独立于节点本地状态的单调检查点仍待实现。
- target 路径固定为 `cores/{core}/{version}/linux/{本机架构}/{官方文件名}`；只接受 Xray、sing-box、mita 的固定资产映射。自定义元数据严格绑定由 SHA-256 派生的制品 ID、Core、版本、OS/架构、`upstream-prebuilt`、固定归档格式、source ID、审核记录 ID 和明确的上游签名状态。拒绝重复或未知字段、错误绑定、缺少 SHA-256 和超过 512 MiB 的 target。
- 下载仅访问固定 GitHub Release asset URL，最多 5 次跳转到允许的 GitHub 官方资产/CDN 主机，禁用代理并拒绝非公网 DNS 地址。下载字节按 TUF length 与 SHA-256 重新校验，成功后才以摘要名、`0400` 权限原子发布到私有缓存；错误字节和中断下载不会留下可用缓存文件。
- 本地工具、远程 Agent 和 Helper 检查 TUF 条目中的 `review_id` 和上游签名状态，并拒绝 `unverified`。这套客户端与发布工具供现有部署和历史测试过渡使用。[旧版 TUF 手册](./phase-3-release.md#4-迁移前的-tuf-调试手册)

## 当前验证边界

早期单签名与 TUF 回归测试记录留作历史追溯。当前官方版本选择、摘要绑定及任务领取流程仍需在目标 Linux 节点完成验收；生产 NTS 和故障恢复也待复验。Linux arm64 目前仅有构建记录。[分阶段开发流程](./phased-development-workflow.md) · [能力矩阵](./core-compatibility.md)

## 已执行检查

| 检查 | 结果 | 环境/范围 |
|---|---|---|
| 单管理员 Xray 选版与后台签发 | 通过，代码 `11743c6`，测试时钟修正 `51151a6`（2026-11-21） | `ro` 的 Debian amd64 隔离检出通过全量 `scripts/check-static.sh`、定向竞态测试和 Master、Agent 及签发器的 amd64/arm64 构建。集成测试覆盖六类操作、架构筛选、已提交版本绑定、请求重试、确认及 MFA，以及单机和独立检查点。临时 Debian 容器用真实 Cloudflare NTS 和测试签名清单运行独立签发进程，验证认证、节点范围、未批准摘要拒绝、幂等重放及清单防回滚。 |
| 单机 Master 无独立检查点 | 通过（2026-11-21） | 在 `ro` 上通过全量 `bash scripts/check-static.sh`。同时配置 Xray 和 Agent/Helper 远程更新策略，使用测试证书启动真实 Master 并通过 HTTPS 健康检查。单机和独立检查点两种配置均通过远程任务、在线租约、备用制品、更新回执及并发互斥的定向竞态测试。独立检查点仍拒绝协调恢复的旧快照。 |
| Master 远程发起 Agent/Helper 成对更新 | 通过，提交 `e66e9af`（2026-11-21） | `ro` 的 `/root/mcui` 隔离检出，Debian 13 amd64、Go 1.27.4、Node.js 26.13.1、pnpm 12.17.0。全量 `bash scripts/check-static.sh`、Master/监督器竞态检查、systemd 单元验证、amd64/arm64 ZIP 构建和 SHA-256 校验通过。涵盖独立签名与凭据、节点绑定、伪造和损坏制品拒绝、任务互斥、TLS 下载、提交和回退、过期处理、回执重试与数据库迁移。arm64 仅验证构建和制品摘要。 |
| 成对更新写满与断电恢复 | 通过，提交 `e66e9af`（2026-11-21） | `TestRuntimeRollbackWithFullFilesystem` 在 2 MiB tmpfs 上实际填满数据块，候选切换后的状态提交触发 `ENOSPC`。监督器释放预留空间并恢复旧对，授权序号保持已消费。同一宿主上用测试签名和服务替身启动无网 QEMU 10.0.13 客户机。候选指针切换并持久化后从宿主机强制终止客户机，复用同一 ext4 镜像启动并确认日志恢复、旧版本指针、已消费序号及待回报的回退结果。临时资源已清理。 |
| Agent/Helper 本地成对更新 | 通过，提交 `c8fe41b`（2026-11-21） | `ro` 的 `/root/mcui` 隔离检出。Debian 13 amd64，Go 1.27.4、Node.js 26.13.1、pnpm 12.17.0。`bash scripts/check-static.sh`、`go test -race -count=1 ./internal/{runtimeupdate,agent,helper,taskledger,xrayruntime,artifacttrust}`、`scripts/build-runtime-release.sh` 和 `sha256sum -c SHA256SUMS` 均通过。全量测试包含独立授权、重放和旧清单拒绝、损坏归档拒绝、试运行拒绝未决任务。真实 systemd 临时服务在 `umask 077` 下用测试密钥和测试时钟验证 Agent 启动失败、Helper 启动失败、就绪握手后提交、切换中断后的开机恢复逻辑和本地回退。节点身份、授权序号及清单版本保持。arm64 仅验证构建和制品摘要。 |
| Xray 远程升级、显式降级和卸载 | 通过，提交 `5214c4a`（2026-11-21） | `ro` 的 `/root/mcui` 隔离检出。Debian 13 amd64，Go 1.27.4、Node.js 26.13.1、pnpm 12.17.0。`bash scripts/check-static.sh`、`go test -race -count=1 ./internal/{agent,agenttasks,artifacttrust,corecatalog,helper,lifecycleauth,master,protocol,taskdispatch,xrayruntime}`、`scripts/build-runtime-release.sh` 和 `sha256sum -c SHA256SUMS` 均通过。集成测试覆盖源版本与目标绑定、不同操作的确认校验、旧 Agent 隔离、制品缓存和结果回报。真实 systemd 使用临时单元和合成制品验证失败启动后恢复原版本与运行状态、成功升级、显式降级和卸载。卸载后服务无主 PID，受管版本目录为空。arm64 仅验证构建和制品摘要。 |
| Xray 远程启停 | 通过，提交 `a6b0246`（2026-11-21） | `ro` 的 `/root/mcui` 隔离检出。Debian 13 amd64，Go 1.27.4、Node.js 26.13.1、pnpm 12.17.0。`bash scripts/check-static.sh`、`go test -race -count=1 ./internal/agent ./internal/agenttasks ./internal/helper ./internal/lifecycleauth ./internal/master ./internal/protocol ./internal/taskdispatch ./internal/xrayruntime`、`scripts/build-runtime-release.sh` 和 `sha256sum -c SHA256SUMS` 均通过。集成测试覆盖独立签发、范围校验、旧 Agent 隔离、制品缓存拒绝、真实 TLS 与 Unix socket、终态回报。运行时测试覆盖版本不符、租约拒绝和中断回滚。临时 `mcui-xray.service` 以受限测试进程验证停止、启动、再次停止及 PID，并在测试后清理。arm64 仅验证构建和制品摘要。 |
| Xray 远程安装任务对账 | 通过，提交 `9614a82`（2026-11-21） | `ro` 的 `/root/mcui` 隔离检出，Debian 13 amd64，Go 1.27.4、Node.js 26.13.1、pnpm 12.17.0。`bash scripts/check-static.sh`、`go test -race -count=1 ./internal/agent ./internal/agenttasks ./internal/helper ./internal/master ./internal/taskdispatch ./internal/taskledger ./internal/xrayruntime`、双架构 `scripts/build-runtime-release.sh` 及 `sha256sum -c SHA256SUMS` 均通过。集成测试使用测试签名、真实 TLS 和 Unix socket 验证 Helper 响应丢失、Agent 账本重开、证据缺失时阻塞、过期后无租约补报、重复 ACK 和下一序号派发。生命周期测试模拟提交后及切换中断后重新打开状态，验证任务凭证不匹配、回滚失败和重复对账。arm64 仅验证构建和发布包摘要。 |
| 单运维员授权及官方 Xray 远程安装 | 通过，提交 `b877e61`（2026-11-19） | `ro` 的 Debian 13 amd64 隔离检出通过 `scripts/check-static.sh` 和八个相关 Go 包的竞态测试。独立冒烟试验使用测试检查点、时钟和回环 TLS TUF 仓库。Agent Runner 通过真实 Unix socket 调用 Helper，Helper 通过真实 TLS 向主控确认租约。两者分别直连官方源下载并复验 `v26.10.31`。临时 systemd 单元中的动态用户进程启动成功，生命周期账本为 `committed`。丢弃首次 ACK、重开 Agent 账本、拒绝过期租约并用新租约回放后，安装执行次数仍为 1。 |
| Xray 安装投递和节点结果回放 | 通过（2026-11-19） | `ro` 的隔离检出通过全量 `scripts/check-static.sh` 和相关 Go 竞态测试。主控、Agent 与 Helper 集成测试覆盖指定审批人投递、60 秒租约续订、过期租约拒绝、真实 TLS 和 Unix socket、丢失 ACK 后重放结果且安装只调用一次。测试使用临时信任材料、测试时间、制品源和特权安装动作替身。 |
| 主控 Xray 安装审批与清单版本锁定 | 通过（2026-11-19） | `ro` 隔离检出使用 Go 1.27.4、Node.js 26.13.1 和 pnpm 12.17.0 运行全量 `scripts/check-static.sh` 和六个相关 Go 包的竞态测试。覆盖 MFA 复验、角色及 CSRF 拒绝、预留槽冲突及过期接续、签发证据先登记、签名任务与原提案一致性、检查点修订推进，以及拒绝不同的 Core 委派版本。使用测试密钥与测试时钟。 |
| Xray 安装双人审批与签发 | 通过，提交 `57ae0d9` 和 `3adee1b`（2026-11-18） | `ro:/root/mcui` 全量 `scripts/check-static.sh` 及签发、可信时间、Xray 生命周期和制品缓存的竞态测试通过。使用临时测试密钥和 chrony 4.6.1 的私有网络及挂载命名空间，以 `chronyd -x` 验证真实 NTS 签发、OpenSSL 验签、相同证据幂等重试及同序号冲突拒绝。普通 NTP 下签发被拒且账本保持空白。已清理临时进程和文件。正式独立信任与远程投递待接入。[签发说明](./phase-3-approval.md) |
| 主控双库回滚检测 | 通过，提交 `405771d`（2026-11-18） | `ro:/root/mcui` 全量检查、主控和检查点竞态测试、真实主控与检查点进程的 mTLS 恢复演练通过。旧两库和旧 journal 一并恢复时拒绝启动，外部 revision 保持。独立主机上的生产恢复仍待验收。[阶段 2 验证记录](./phase-2-progress.md#验证状态) |
| 独立检查点服务 | 通过，提交 `1ba38ce`（2026-11-18） | `ro:/root/mcui` 完整 `scripts/check-static.sh`、检查点竞态测试及临时 systemd 服务冒烟通过。验证 mTLS 拒绝未登记客户端、旧 journal 拒绝、CAS 幂等和重启后 revision 持久化。[阶段 2 验证记录](./phase-2-progress.md#验证状态) |
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
