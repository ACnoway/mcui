# 阶段 3 制品发布

Core 安装直接使用各项目官方 GitHub Releases。安装 Xray 时，管理员在节点面板选择一个已发布的稳定版本；Master 根据固定的 Xray 仓库读取该版本和节点架构对应的官方制品，并把精确版本、架构和 SHA-256 签入生命周期任务。节点只从固定的官方来源下载，并校验文件长度和 SHA-256。

这条流程不需要单独维护 Core 发布公钥或签名清单。Master 在上游 API 提供制品摘要时核对该摘要；未提供时由 Master 下载官方文件并计算摘要。Agent 与 Helper 仍使用专用任务公钥核验任务。Agent/Helper 成对更新使用独立的运行时签名和节点授权流程，见[成对更新手册](./phase-3-runtime-update.md)。

## 1. 发布位置和信任边界

- Xray、sing-box 和 mita 的 Core 制品来自各自固定的官方仓库。当前远程生命周期管理支持 Xray；面板列出该节点架构有对应制品的已发布稳定版本，管理员明确选择安装、升级或降级目标。
- Master 解析所选标签对应的官方 Release，接受精确的预期资产名称和 GitHub 官方下载地址。节点再次解析同一个版本和架构，并用任务中的摘要校验下载结果。版本发布或资产替换后，旧任务的摘要不匹配时会失败。
- Xray 任务签名密钥只负责授权节点、动作和精确的 Core 版本。它与只读状态任务密钥、SSH/GitHub 凭据分开管理。节点不需要 Core 发布公钥或手工更新签名清单。
- MCUI 在 `ACnoway/mcui` 的 GitHub Releases 发布 Compose 配置、预构建主控和通用 Agent 安装器；配套主控镜像由 GitHub Container Registry 分发。[主控打包](./master-deployment.md) · [Agent 接入](./phase-1-operations.md#节点首次接入)

## 2. MCUI 发布和制品检查

1. Core 版本目录读取上游 GitHub Releases。管理员在执行安装操作时选定版本；Master 检查 Release 已发布、不是草稿或预发布，并确认该节点架构的 Xray ZIP 存在。
2. 如果 GitHub API 提供 asset SHA-256，Master 将它用于任务摘要并在节点端复核；如果上游没有摘要，Master 下载该固定官方资产并计算 SHA-256。节点下载时再次检查任务绑定的文件长度和摘要，并严格校验解压内容。
3. Core 的安全更新由上游发布和项目兼容矩阵管理，无需每个版本另行生成、签署和发布 MCUI 清单。出现不兼容版本时，管理员可在面板选择仍兼容的已发布版本。
4. 构建 MCUI 自身更新包可使用 `bash scripts/build-runtime-release.sh NEW_DIRECTORY`。Agent 和 Helper 的成对 ZIP 仍由运行时专用密钥签署，节点更新还需独立授权。[成对更新手册](./phase-3-runtime-update.md)

### 标签和预发布

- `vX.Y.Z-alpha.N` 用于早期验证。主要功能已经可以试用，部署流程、接口或数据结构仍可能调整。
- `vX.Y.Z-beta.N` 用于功能基本齐全后的验收。重点验证从零部署、节点接入、升级和兼容性。
- `vX.Y.Z` 用于通过验收的正式版。主、次和补丁版本号使用无前导零的非负整数。每个预发布阶段的序号从 `1` 开始。示例顺序为 `v0.1.0-alpha.1`、`v0.1.0-alpha.2`、`v0.1.0-beta.1`、`v0.1.0`。[语义化版本规范](https://semver.org/lang/zh-CN/)

**Publish MCUI release** 在推送新标签时运行项目检查，从该标签构建 amd64 和 arm64 制品，并上传到 GitHub Release。每个架构提供 `mcui-master-linux-<arch>.tar.gz`（主控和 Web 文件）和 `mcui-agent-linux-<arch>.zip`（Agent 和 Helper），另附 `SHA256SUMS-binaries`。

Alpha 和 Beta 会自动公开为 Pre-release；正式版按稳定标签发布。Core 版本仍从各 Core 项目的官方 Releases 选择。可从已包含工作流的提交推送测试标签。

```sh
git tag -a v0.1.0-alpha.1 -m v0.1.0-alpha.1
git push origin refs/tags/v0.1.0-alpha.1
```

本地可用 `bash scripts/build-binary-release.sh NEW_DIRECTORY` 构建同样的归档，并运行 `sha256sum --check SHA256SUMS-binaries` 核验。Agent/Helper 的远程成对更新还需单独的发布签名和节点授权。[版本工作流](../.github/workflows/release.yml) · [成对更新手册](./phase-3-runtime-update.md)

### 发布 Compose 和通用 Agent

1. 推送 `vX.Y.Z-alpha.N`、`vX.Y.Z-beta.N` 或 `vX.Y.Z` 标签。工作流先在 Release 草稿中准备对应提交的主控和 Agent 二进制。
2. Alpha、Beta 和稳定版都会自动构建 amd64/arm64 Compose 镜像、通用 Agent 安装器、Compose 文件和摘要，再上传到对应 Release。每个 Release 附带的 Compose 文件默认固定到自己的镜像版本；预发布镜像不改动 `latest`，稳定版成功后才更新 `latest`。可设置 `MCUI_MASTER_IMAGE` 覆盖默认镜像标签。
3. 首次发布后，将 GHCR 的 `mcui-master` 包设为公开。后续 Actions 用仓库自动提供的 `GITHUB_TOKEN` 和 `packages: write` 发布，不需要 PAT 或额外密钥。检查镜像可匿名拉取，Release 安装器摘要与配套镜像中 `/opt/mcui/release/agent-release` 的摘要一致。

可用 `bash scripts/build-compose-release.sh NEW_DIRECTORY vX.Y.Z-alpha.N`（或 `beta.N`、稳定标签）在隔离环境构建同样的制品。通用安装器从面板命令接收 Xray 生命周期任务公钥；Core 发布公钥不再随安装器分发。[发布工作流](../.github/workflows/release-deployment.yml)

### 生产发布验收

- 验证一键脚本和 Compose 的发布入口、首次凭据、证书接入，以及从面板命令安装空 Agent。验证管理员能选择官方稳定版并安装精确的 Xray 制品。
- 使用配套的发布镜像和 Compose 安装程序在干净环境启动，验证复用已有宿主机时间同步服务，以及缺少服务时自动安装并启用。验证容器独立取得 NTS 可信时间、容器重启和临时网络中断后恢复签发。[可信任务时间排查](./master-deployment.md#可信任务时间排查)
- 发布检查覆盖 Go、前端锁文件、镜像及已支持的 Core 版本，记录修复版本和升级方式。验证补丁的签名、安装和回滚。
- 用生产任务信任材料完成节点部署，确认 chrony 实际通过 NTS 使用 `time.cloudflare.com`，验证任务签名、制品摘要、安装及结果回报。单机用户按单机流程备份和恢复。启用了独立检查点的部署另外验证旧快照拒绝。[单机备份恢复](./phase-2-operations.md#单机运行与备份恢复)
- 使用独立的运行时发布密钥和节点更新授权密钥验收远程成对更新，在待发布的节点配置上复验断电和磁盘写满后的恢复与结果回报。[成对更新](./phase-3-runtime-update.md)
- 记录对应提交、支持平台、部署与恢复结果。常规开发使用隔离节点和测试信任材料。[阶段 3 开发进度](./phase-3-progress.md#后续工作)

## 3. 旧 TUF 实现

旧版 TUF 客户端、已签发任务和历史验证材料仍保留在代码库中，供需要重现旧部署的用户使用。新安装流程不再要求复制 TUF 根、Core 发布公钥或 Core 签名清单。Agent/Helper 成对自更新继续使用自己的签名材料，见[更新手册](./phase-3-runtime-update.md)。

## 4. 迁移前的 TUF 调试手册

本节只适用于复现历史 TUF 实现与旧部署；新 Core 安装不使用此流程。

`mcui-tuf` 生成、签署并检查标准 TUF metadata。节点以独立渠道分发的离线根为起点，在 HTTPS 仓库刷新 metadata，再前往固定 GitHub 官方源取制品。

### 分配签名角色

TUF 使用 Ed25519 密钥签署发布清单。私钥以 PKCS#8 PEM 保存，由保管人本地签名。公钥及指纹用于生成离线信任根和委派。节点以离线分发的 `offline-root.json` 验证发布清单。部署 SSH、GitHub 上传权限和远程任务签发各使用独立凭据。

| 角色 | 签署内容 | 当前密钥分配 |
|---|---|---|
| `root` | 顶层角色的公钥与阈值 | 3 把，至少 2 个签名 |
| `targets` | Core 和 Agent/Helper 两个发布委派 | 3 把，至少 2 个签名 |
| `core-targets` | 允许安装的 Core 版本、架构、大小和摘要 | 3 把，至少 2 个签名 |
| `runtime-targets` | 允许更新的 Agent/Helper 制品 | 3 把，至少 2 个签名 |
| `snapshot` | 各版本清单的版本、长度和摘要 | 1 把单用途在线密钥 |
| `timestamp` | 当前快照的版本和摘要、时间戳有效期 | 1 把单用途在线密钥 |

TUF 发布工具和客户端共要求 14 把互不复用的密钥。角色阈值用于发布制品清单。运维员在面板发起单次安装走[运维授权与独立签发](./phase-3-approval.md)。

`root-keys.json` 是含 `root`、`targets`、`snapshot`、`timestamp` 的对象，值分别为包含规定数量公钥文件路径的数组。`delegation-keys.json` 使用同一格式，键为 `core-targets`、`runtime-targets`。相对路径以各自清单所在目录为基准。集成测试临时产生的密钥只用于该次测试。

### 审核制品、准备并逐人签名

每个准备发布的版本和架构做一次取件核验，可以用一条记录保存结果。

1. 从固定上游 GitHub Releases 下载精确版本、架构对应的原始资产。记录官方链接、文件名、字节长度和 `sha256sum` 的结果，并与上游公布的摘要核对，例如 Release API 的 `digest` 或附件 `.dgst`。
2. 核对归档内容、可执行文件架构和许可证，关联该制品对应的构建或运行验证。上游有可验证签名时用其公钥验签，成功后记为 `verified`。确认上游未提供签名时记为 `not-provided`。未核实的制品暂缓发布。
3. 为核验记录分配 `review_id`，将其与 `core`、`version`、`architecture`、`length`、`sha256` 和 `upstream_signature_status` 写入 `core-reviews.json` 数组，用 `mcui-tuf` 生成并签署清单。撤销时在新版本的清单移除该条目。

```sh
go build -trimpath -o mcui-tuf ./cmd/mcui-tuf
mkdir signed
./mcui-tuf prepare -role root -version 1 -expires "$ROOT_EXPIRY" \
  -input root-keys.json -output root-unsigned.json
./mcui-tuf prepare -role targets -version 1 -expires "$TARGETS_EXPIRY" \
  -input delegation-keys.json -output targets-unsigned.json
./mcui-tuf prepare -role core-targets -version 1 -expires "$CORE_EXPIRY" \
  -input core-reviews.json -output core-unsigned.json
./mcui-tuf prepare -role runtime-targets -version 1 -expires "$RUNTIME_EXPIRY" \
  -output runtime-unsigned.json
```

签名人应核对版本、到期时间、角色和内容。前一位输出的 metadata 作为后一位的输入，每次 `sign` 读取一把本地私钥。下面是单次签名示例。

```sh
./mcui-tuf sign -role core-targets -input core-unsigned.json \
  -key "$MY_CORE_SIGNING_KEY" -output core-partial.json
```

依次收齐各角色签名，保存离线信任根 `offline-root.json`，并将签好的 `targets.json`、`core-targets.json` 和 `runtime-targets.json` 放入 `signed/`。

#### Agent/Helper 更新制品

`bash scripts/build-runtime-release.sh NEW_DIRECTORY` 从同一源码构建两架构的 Agent/Helper ZIP，并生成 `SHA256SUMS`。每个 ZIP 只含该架构的 `mcui-agent` 和 `mcui-helper`。如需复现历史 TUF 签发，对各架构核验源码、构建、长度和散列，将 `version`、`architecture`、`length`、`sha256`、`review_id` 写成 JSON 数组，通过 `prepare -role runtime-targets -input INVENTORY` 准备元数据，再由独立保管人签名。现有成对监督器使用独立的单签清单及节点更新授权。

在签好的三个 targets 文件上生成 snapshot，并用 snapshot 单用途密钥签名。然后按同样步骤生成 timestamp 并用 timestamp 单用途密钥签名。

```sh
./mcui-tuf prepare -role snapshot -version 1 -expires "$SNAPSHOT_EXPIRY" \
  -input signed -output snapshot-unsigned.json
./mcui-tuf sign -role snapshot -input snapshot-unsigned.json \
  -key "$SNAPSHOT_SIGNING_KEY" -output signed/snapshot.json
./mcui-tuf prepare -role timestamp -version 1 -expires "$TIMESTAMP_EXPIRY" \
  -input signed -output timestamp-unsigned.json
./mcui-tuf sign -role timestamp -input timestamp-unsigned.json \
  -key "$TIMESTAMP_SIGNING_KEY" -output signed/timestamp.json
```

### 核验并生成发布目录

```sh
./mcui-tuf assemble -root offline-root.json -input signed -output generation-1
# 后续发布用当前线上版本的完整公开目录作为 -previous。
./mcui-tuf assemble -root offline-root.json -input signed -previous generation-1 -output generation-2
```

发布前工具验证阈值、委派、有效期、逐版本 root 轮换、snapshot/timestamp 摘要绑定及版本单调性。生成的目录只含公开 metadata。HTTPS 仓库可在一次原子切换中发布目录，或先上传全部版本化文件，再最后发布 `timestamp.json`。对于逐文件发布，保留现在线上仍有效的版本化 metadata，避免正在刷新中的客户端取件失败。

更新时递增变更角色的版本。相同版本的签署文件保留原始字节。轮换 root 时把完整的 `2.root.json`、`3.root.json` 等连续历史放入 `signed/`，每版均收齐旧 root 和新 root 的阈值签名。撤销 Core 目标时重新签署 Core metadata、snapshot 和 timestamp。旧阈值不可用时按带外恢复流程重新建立信任。

### TUF 调试仓库的托管

可将 `assemble` 生成的公开 JSON 原样部署到 GitHub Pages 的固定路径，例如 `https://OWNER.github.io/REPO/tuf/`。每次部署携带当前 `timestamp.json`、它引用的版本化文件、完整的 root 轮换历史，以及旧 timestamp 仍可能引用的版本化文件。节点配置该 HTTPS 地址并通过独立渠道获取信任根。GitHub Releases 可用于分发 ZIP 或存档一代签署后的公开 JSON。私钥继续保存在签发环境。[GitHub Pages 发布配置](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)

当前 TUF 客户端只允许同域 HTTPS 元数据跳转。GitHub Releases 的附件链接会重定向到资产 CDN。若将 Releases 直接作为 TUF 元数据源，需要增加对固定仓库路径及 GitHub 资产 CDN 的支持，并确保每代发布自带可继续使用的版本化文件。[GitHub Releases 附件链接](https://docs.github.com/en/repositories/releasing-projects-on-github/linking-to-releases)
