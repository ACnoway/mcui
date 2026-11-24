# 阶段 3 制品发布

生产发布采用 **GitHub Releases 和单个 Ed25519 签名的制品清单**，由一位维护者管理发布密钥。签发工具和 Xray 安装客户端已接入此格式，首份生产清单仍待审核和发布。TUF 流程用于旧任务收尾和历史验证。

## 1. 发布位置和密钥

- Xray、sing-box 和 mita 使用各自官方 GitHub Releases 上的原始二进制包。MCUI 的安装器仅选择已核验并登记进有效签名清单的版本与架构。
- V1 在 `ACnoway/mcui` 的 GitHub Releases 发布 Compose 配置、预构建的主控安装程序和通用 Agent 安装器，通过 GitHub Container Registry 分发配套主控镜像。安装器包含 amd64 和 arm64 二进制。Agent/Helper 成对更新 ZIP 使用独立的更新流程。[主控打包](./master-deployment.md) · [Agent 接入](./phase-1-operations.md#节点首次接入)
- 先以草稿上传 `manifest.json` 和 `manifest.json.sig`，再将包含两个附件的 Release 发布为 Latest。客户端通过固定仓库的 `releases/latest` 取得标签，再从该标签取两个文件。给已发布的 Latest Release 更换附件会导致同版本内容冲突。每次变更发新标签和更高版本，保留清单引用的制品版本。可以单独发布清单更新，复用已发布的 ZIP。每个设为 Latest 的 Release 都需带这两个文件。
- 维护者在离线签发环境保管一把 Ed25519 发布私钥。通过可信安装包或带外配置为节点预置对应公钥并核对指纹。发布私钥与任务签发、SSH 和 GitHub 上传凭据分开。更换或撤销公钥通过节点本地管理完成。

## 2. 取件核验和发布

1. 每个版本和架构核对一次。记录官方地址、文件名、长度和 SHA-256，与上游公布的摘要比对（如有）。检查归档成员、可执行文件架构和许可证，关联相应的构建或运行结果。上游有可验证签名时核验并记录结果。
2. 构建 MCUI 自身更新包可使用现有 `bash scripts/build-runtime-release.sh NEW_DIRECTORY`。同一架构的 Agent 和 Helper 作为一个 ZIP 发布，取件记录关联源码提交和构建结果。供成对监督器使用的清单只包含 `mcui-runtime` 条目，由运行时专用发布密钥签署。节点授权使用另一把密钥。[成对更新手册](./phase-3-runtime-update.md)
3. 将通过核验的条目填入[清单格式](./agent-technical-design-v1.0.md#62-制品清单最小字段)。发布时递增 `manifest_version`（正整数，最大值为 9007199254740991），设置 RFC 3339 `expires_at`。组件为 `xray`、`sing-box`、`mita` 或 `mcui-runtime`，操作系统为 `linux`，架构为 `amd64` 或 `arm64`。源标识分别为 `github:XTLS/Xray-core`、`github:SagerNet/sing-box`、`github:enfein/mieru` 和 `github:ACnoway/mcui`。ID 为 `<组件>-<架构>-<小写SHA256>`，其中 Xray 使用前缀 `xray-manifest-`。上游制品的 `build_options` 为 `upstream-prebuilt`，已核验签名记为 `verified`，确认未提供签名记为 `not-provided`。MCUI ZIP 使用 `mcui-build:<40位源码提交SHA>` 与 `not-applicable`，文件名为 `mcui-runtime-linux-<架构>.zip`。
4. 用发布私钥对 `manifest.json` 的原始字节签名，将 64 字节 Ed25519 分离签名写入 `manifest.json.sig`。使用节点预置公钥复验后发布这两个文件。撤销制品时在下一版清单移除相应条目，`artifacts: []` 可一次撤销所有制品。

```sh
go build -trimpath -o mcui-manifest ./cmd/mcui-manifest
./mcui-manifest sign -private-key "$RELEASE_PRIVATE_KEY" -manifest manifest.json -signature manifest.json.sig
./mcui-manifest verify -public-key "$RELEASE_PUBLIC_KEY" -manifest manifest.json -signature manifest.json.sig
```

私钥使用 Ed25519 PKCS#8 PEM，Unix 上仅所有者可访问。公钥支持 PKIX PEM 或标准 Base64 编码的 32 字节原始公钥。核对 `verify` 输出中的原始公钥 SHA-256 指纹、清单版本及原始字节摘要。签发命令拒绝覆盖已有签名文件。

任务绑定节点、动作和清单中的精确制品。V1 面板由有效清单筛选可安装版本，默认选择当前节点可安装的最新稳定版，并在创建任务时锁定实际版本与摘要。Agent 与 Helper 分别核验清单签名和版本，再按相同长度和 SHA-256 校验官方源或主控缓存的字节。[节点启动恢复](./phase-3-operations.md#进程中断恢复验收) · [制品信任方案](./artifact-trust.md)

### 手工发布

1. 选定通过检查的 `master` 提交和发布标签 `vX.Y.Z`，创建并推送该标签。从同一标签的干净检出构建全部制品。
2. 运行下列构建命令，将两个安装程序和两个运行时 ZIP 汇总到上传目录，生成并复核统一的 `SHA256SUMS`。如随版交付 Compose，将同一份 Master 构建结果打成版本化镜像，并在发布说明中列出镜像摘要。
3. 由发布密钥保管者核对审核记录，按本节签发并复验 `manifest.json` 与 `manifest.json.sig`。Git 标签标识 MCUI 源码版本，`manifest_version` 是客户端独立核对的单调递增序号。成对更新使用独立发布签名和节点授权。
4. 在 GitHub 创建该标签的草稿，上传安装程序、ZIP、`SHA256SUMS` 及两份清单附件。核对草稿附件、版本和摘要后发布。供客户端取件的稳定 Release 必须包含两份有效清单附件，再设为 Latest。发布后核对 `releases/latest` 指向该标签，并用节点预置的公钥复验下载的清单。

```bash
set -euo pipefail
# RELEASE_TAG 和 RELEASE_COMMIT 由维护者填入。
git tag -a "$RELEASE_TAG" "$RELEASE_COMMIT" -m "$RELEASE_TAG"
git push origin "refs/tags/$RELEASE_TAG"

# 以下命令在与该标签对应的干净 Linux 检出中执行。
test "$(git rev-parse HEAD)" = "$(git rev-parse "$RELEASE_TAG^{commit}")"
bash scripts/check-static.sh
out=$(mktemp -d)
mkdir "$out/assets"
bash scripts/build-master-release.sh "$out/master"
bash scripts/build-agent-installer.sh "$out/assets/install-mcui-agent.sh"
bash scripts/build-runtime-release.sh "$out/runtime"
cp "$out/master/install-mcui-master.sh" "$out/assets/"
cp "$out/runtime"/mcui-runtime-linux-*.zip "$out/assets/"
(
  cd "$out/assets"
  sha256sum install-mcui-master.sh install-mcui-agent.sh \
    mcui-runtime-linux-amd64.zip mcui-runtime-linux-arm64.zip > SHA256SUMS
  sha256sum -c SHA256SUMS
)
```

把经过离线签名并复验的两份清单附件放入 `"$out/assets"`。下面的第一条命令只创建草稿，最后一条发布草稿。

```bash
gh release create "$RELEASE_TAG" --verify-tag --draft --generate-notes \
  "$out/assets/install-mcui-master.sh" "$out/assets/install-mcui-agent.sh" \
  "$out/assets/mcui-runtime-linux-amd64.zip" "$out/assets/mcui-runtime-linux-arm64.zip" \
  "$out/assets/SHA256SUMS" "$out/assets/manifest.json" "$out/assets/manifest.json.sig"
# 审核草稿后发布。
gh release edit "$RELEASE_TAG" --draft=false --latest
```

标签只标识 Git 中的提交。推送标签后，通过 GitHub 页面或 CLI 创建 Release 草稿。[创建 Release](https://cli.github.com/manual/gh_release_create)

### 发布 Compose 和通用 Agent

1. 维护者审核制品并离线签发清单。把项目发布公钥写入仓库 Actions 变量 `MCUI_RELEASE_PUBLIC_KEY`。部署者无需配置此变量。
2. 推送 `vX.Y.Z` 标签，为其创建稳定 Release 草稿，并上传 `manifest.json` 和 `manifest.json.sig`。
3. 在 `master` 上手动运行 **Publish MCUI deployment**，输入该标签。工作流从标签构建并核验清单，推送两架构的版本化主控镜像，上传安装器、Compose 配置和摘要，然后发布 GitHub Release 并更新镜像的 `latest` 标签。
4. 首次发布后，将 GHCR 的 `mcui-master` 包设为公开。检查镜像可匿名拉取，Release 安装器摘要与配套镜像中 `/opt/mcui/release/agent-release` 的摘要一致。

可用 `bash scripts/build-compose-release.sh NEW_DIRECTORY vX.Y.Z release.pub manifest.json manifest.json.sig` 在隔离环境构建同样的制品。通用安装器内含项目发布公钥，面板在生成安装命令时传入部署的任务签发公钥。独立发布的清单更新可保留原版本 Agent 安装器，镜像中固定的下载版本继续可用。[发布工作流](../.github/workflows/release-deployment.yml)

### 生产发布验收

- 维护者核验首批制品和发布公钥，签发并发布首份生产清单。
- 验证一键脚本和 Compose 的发布入口、首次凭据、证书接入，以及从面板命令安装空 Agent。验证管理员选择默认版本后使用核准的官方 Xray 制品。
- 发布检查覆盖 Go、前端锁文件、镜像及已支持的 Core 版本，记录修复版本和升级方式。验证补丁的签名、安装和回滚。
- 用生产信任材料完成节点部署，确认 chrony 实际通过 NTS 使用 `time.cloudflare.com`，验证签名清单、安装及结果回报。单机用户按单机流程备份和恢复。启用了独立检查点的部署另外验证旧快照拒绝。[单机备份恢复](./phase-2-operations.md#单机运行与备份恢复)
- 使用独立的运行时发布密钥和节点更新授权密钥验收远程成对更新，在待发布的节点配置上复验断电和磁盘写满后的恢复与结果回报。[成对更新](./phase-3-runtime-update.md)
- 记录对应提交、支持平台、部署与恢复结果。常规开发使用隔离节点和测试信任材料。[阶段 3 开发进度](./phase-3-progress.md#后续工作)

## 3. 从当前 TUF 实现迁移

1. 先为节点配发发布公钥和经带外核对的当前清单，按[节点手册](./phase-3-operations.md)初始化 Agent 状态及本地工具和 Helper 共用的特权清单状态。
2. 更新 Master 和独立签发工具。已投递的 TUF 任务仍可由旧模式节点领取和回报，切换节点前先收尾或对账。旧的未投递提案不再投递，按原任务序号规则处理保留槽后，用当前单签清单重建提案。
3. 协调切换节点的 Agent、Helper 和本地工具。新提案使用格式版本 3，签名信封中的 Xray 制品 ID 带 `xray-manifest-` 前缀，Master 仅向声明 `install=xray-manifest-v1` 的节点租出新任务。旧任务的 `manifest_version` 仍指 TUF 的 `core-targets` 委派版本。保留原身份、任务账本、已部署版本和恢复状态。

## 4. 迁移前的 TUF 调试手册

本节适用于复现现有 TUF 实现与历史验证。生产发布按上面的单签清单方案实施。

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
