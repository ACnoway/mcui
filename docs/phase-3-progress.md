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

## 后续工作

1. 实现并验收 TUF targets 信任、上游签名事实核验及审核记录；当前缓存的 GitHub API digest 不能替代这些授权步骤。
2. 实现 Agent 直连官方源的固定源下载和未来精确缓存备用路径，设置请求/响应大小与时间限制、重定向主机限制、摘要/签名校验及缓存回退条件。任务绑定制品 ID、精确版本、架构和摘要，不接受任意 URL。
3. 建立高危操作 MFA 复验和独立审批后，增加签名安装/升级/显式降级/卸载任务及 Helper 固定操作。
4. 为 Xray 增加不可变版本目录、固定 systemd unit、独立低权限账号、健康确认、LKG 恢复和启动对账。
5. 实现 Agent/Helper 独立授权更新、旧版本监督、自动恢复和本地人工修复；完成失败恢复演练前保持远程自身更新关闭。
6. 在 Debian 13.7 amd64/arm64 分别测试制品拒绝、下载中断、磁盘不足、错误架构、恶意归档、启动失败和恢复；按证据更新能力矩阵。

## 当前验证边界

目录和备用缓存测试覆盖固定源解析、分页、上游 URL 校验、版本选择、存储 manifest、下载长度/摘要、跳转主机、缓存原子替换和失败保留；不覆盖发布密钥、TUF、二进制真实性或节点安装。阶段 3 退出门槛见[分阶段开发流程](./phased-development-workflow.md)；任何 Core 在兼容矩阵实测前仍是未验证状态。

## 已执行检查

| 检查 | 结果 | 环境/范围 |
|---|---|---|
| `scripts/check-static.sh` | 通过，提交 `d17c468` | `ssh ro`，`/root/mcui`，Debian 13.7 amd64；Go 1.27.4、Node.js 26.13.1、pnpm 12.17.0 |
| Go 格式、vet、构建与测试 | 通过 | 包含新目录解析/链接校验/缓存测试、Master 管理员认证测试及全量现有测试 |
| Linux amd64/arm64 构建 | 通过 | 交叉构建；没有 arm64 实机或干净 VM 证据 |
| V1/V2 协议向量 | 通过 | 分别 4 个/9 个及 3 个/29 个正反例 |
| Web 冻结依赖与生产构建 | 通过 | `pnpm install --frozen-lockfile`、`pnpm build` |
| 官方 API 在线 payload smoke test | 通过（2026-11-17） | 每页 10 条解压后约 1.3 MiB（Xray）、3.4 MiB（sing-box）、0.8 MiB（mita）；100 条请求为 5.6–32.1 MiB，因此采用按需分页 |
| Core 下载/安装、systemd 故障恢复 | 未执行 | 当前提交未包含安装、备用制品、Helper 或 Core 生命周期运行时 |
