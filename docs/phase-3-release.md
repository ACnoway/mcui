# 阶段 3 制品发布

生产发布采用 **GitHub Releases 和单个 Ed25519 签名的制品清单**，由一位维护者管理发布密钥。方案已确定，客户端、签名工具和生产发布尚待实现。当前代码仍通过本页后半部分的 TUF 流程运行。

## 1. 发布位置和密钥

- Xray、sing-box 和 mita 继续从各自的官方 GitHub Releases 下载。MCUI 自建的 Agent/Helper 双架构 ZIP 放在 `ACnoway/mcui` 的 GitHub Releases。
- 将 `manifest.json` 和 `manifest.json.sig` 一起上传到同一个 MCUI Release。客户端从固定仓库取得当前稳定 Release 的标签，再从该标签取两个文件。每次变更发布新一代清单，保留清单引用的制品版本。可以单独发布清单更新，复用已发布的 ZIP。
- 维护者在离线签发环境保管一把 Ed25519 发布私钥。通过可信安装包或带外配置为节点预置对应公钥并核对指纹。发布私钥与任务签发、SSH 和 GitHub 上传凭据分开。更换或撤销公钥通过节点本地管理完成。

## 2. 取件核验和发布

1. 每个版本和架构核对一次。记录官方地址、文件名、长度和 SHA-256，与上游公布的摘要比对（如有）。检查归档成员、可执行文件架构和许可证，关联相应的构建或运行结果。上游有可验证签名时核验并记录结果。
2. 构建 MCUI 自身更新包可使用现有 `bash scripts/build-runtime-release.sh NEW_DIRECTORY`。同一架构的 Agent 和 Helper 作为一个 ZIP 发布，取件记录关联源码提交和构建结果。
3. 将通过核验的条目填入清单。每项固定组件、精确版本、平台、架构、文件名、来源标识、归档格式、长度和 SHA-256，并关联核验记录。发布时递增 `manifest_version`，设置 `expires_at`。
4. 用发布私钥对 `manifest.json` 的原始字节签名，将 64 字节 Ed25519 分离签名写入 `manifest.json.sig`。使用节点预置公钥复验后发布这两个文件。撤销制品时在下一版清单移除相应条目。

任务仍绑定节点、动作和清单中的精确制品。Agent 与 Helper 分别核验清单签名和版本，再按相同长度和 SHA-256 校验官方源或主控缓存的字节。对账和启动恢复按照[节点操作手册](./phase-3-operations.md#进程中断恢复验收)。清单字段和防回退规则见[制品信任方案](./artifact-trust.md)。

## 3. 从当前 TUF 实现迁移

先为节点配发发布公钥，再协调切换 Master、Agent、Helper 和本地工具。迁移前处理已投递的旧任务，未投递的旧提案按新清单重建。现有任务的 `manifest_version` 指 TUF 的 `core-targets` 委派版本。新提案使用单签清单的独立版本序列。迁移保留原身份、任务账本、已部署版本及本地恢复状态。

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

`bash scripts/build-runtime-release.sh NEW_DIRECTORY` 从同一源码构建两架构的 Agent/Helper ZIP，并生成 `SHA256SUMS`。每个 ZIP 只含该架构的 `mcui-agent` 和 `mcui-helper`。如需签署候选制品，对各架构核验源码、构建、长度和散列，将 `version`、`architecture`、`length`、`sha256`、`review_id` 写成 JSON 数组，通过 `prepare -role runtime-targets -input INVENTORY` 准备元数据，再由独立保管人签名。组装工具核验版本、架构、固定路径和专用委派。自动切换、服务健康监督、旧版恢复和远程更新通道仍待实现。

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
