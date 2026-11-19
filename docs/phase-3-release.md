# 阶段 3 TUF 制品发布

`mcui-tuf` 生成、签署并检查标准 TUF metadata。节点以独立渠道分发的离线根为起点，在 HTTPS 仓库刷新 metadata，再前往固定 GitHub 官方源取制品。

## 1. 分配签名角色

TUF 使用 Ed25519 密钥签署发布清单。私钥以 PKCS#8 PEM 保存，由保管人本地签名。公钥及指纹用于生成离线信任根和委派。节点以离线分发的 `offline-root.json` 验证发布清单。部署 SSH、GitHub 上传权限和远程任务签发各使用独立凭据。

| 角色 | 签署内容 | 当前密钥分配 |
|---|---|---|
| `root` | 顶层角色的公钥与阈值 | 3 把，至少 2 个签名 |
| `targets` | Core 和 Agent/Helper 两个发布委派 | 3 把，至少 2 个签名 |
| `core-targets` | 允许安装的 Core 版本、架构、大小和摘要 | 3 把，至少 2 个签名 |
| `runtime-targets` | 允许更新的 Agent/Helper 制品 | 3 把，至少 2 个签名 |
| `snapshot` | 各版本清单的版本、长度和摘要 | 1 把单用途在线密钥 |
| `timestamp` | 当前快照的版本和摘要、时间戳有效期 | 1 把单用途在线密钥 |

当前发布工具和客户端共要求 14 把互不复用的密钥。角色阈值用于发布制品清单。运维员在面板发起单次安装走[运维授权与独立签发](./phase-3-approval.md)。

`root-keys.json` 是含 `root`、`targets`、`snapshot`、`timestamp` 的对象，值分别为包含规定数量公钥文件路径的数组。`delegation-keys.json` 使用同一格式，键为 `core-targets`、`runtime-targets`。相对路径以各自清单所在目录为基准。集成测试临时产生的密钥只用于该次测试。

## 2. 审核制品、准备并逐人签名

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

### Agent/Helper 更新制品

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

## 3. 核验并生成发布目录

```sh
./mcui-tuf assemble -root offline-root.json -input signed -output generation-1
# 后续发布用当前线上版本的完整公开目录作为 -previous。
./mcui-tuf assemble -root offline-root.json -input signed -previous generation-1 -output generation-2
```

发布前工具验证阈值、委派、有效期、逐版本 root 轮换、snapshot/timestamp 摘要绑定及版本单调性。生成的目录只含公开 metadata。HTTPS 仓库可在一次原子切换中发布目录，或先上传全部版本化文件，再最后发布 `timestamp.json`。对于逐文件发布，保留现在线上仍有效的版本化 metadata，避免正在刷新中的客户端取件失败。

更新时递增变更角色的版本。相同版本的签署文件保留原始字节。轮换 root 时把完整的 `2.root.json`、`3.root.json` 等连续历史放入 `signed/`，每版均收齐旧 root 和新 root 的阈值签名。撤销 Core 目标时重新签署 Core metadata、snapshot 和 timestamp。旧阈值不可用时按带外恢复流程重新建立信任。[制品信任方案](./artifact-trust.md)

## 4. 在 GitHub 托管

可将 `assemble` 生成的公开 JSON 原样部署到 GitHub Pages 的固定路径，例如 `https://OWNER.github.io/REPO/tuf/`。每次部署携带当前 `timestamp.json`、它引用的版本化文件、完整的 root 轮换历史，以及旧 timestamp 仍可能引用的版本化文件。节点配置该 HTTPS 地址并通过独立渠道获取信任根。GitHub Releases 可用于分发 ZIP 或存档一代签署后的公开 JSON。私钥继续保存在签发环境。[GitHub Pages 发布配置](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)

当前 TUF 客户端只允许同域 HTTPS 元数据跳转。GitHub Releases 的附件链接会重定向到资产 CDN。若将 Releases 直接作为 TUF 元数据源，需要增加对固定仓库路径及 GitHub 资产 CDN 的支持，并确保每代发布自带可继续使用的版本化文件。[GitHub Releases 附件链接](https://docs.github.com/en/repositories/releasing-projects-on-github/linking-to-releases)
