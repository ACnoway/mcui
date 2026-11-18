# 阶段 3 Xray 本地生命周期

`mcui-xray` 在 Linux amd64/arm64 节点上由本地 root 管理独立的 `mcui-xray.service`。服务使用固定空 JSON 引导配置和独立的低权限 systemd 沙箱，供阶段 3 生命周期验证。现有 Agent 安装器和面板任务继续使用阶段 2 的只读路径。指定版本和架构的产品状态见[能力矩阵](./core-compatibility.md)。

## 1. 准备验证节点

用经核验的源码构建 Linux 二进制。在隔离的 Debian 验证节点执行以下本地部署步骤。

```sh
go build -trimpath -o mcui-xray ./cmd/mcui-xray
install -o root -g root -m 0755 mcui-xray /usr/local/bin/mcui-xray
install -o root -g root -m 0644 deploy/systemd/mcui-xray*.service /etc/systemd/system/
systemctl daemon-reload
mcui-xray initialize
systemctl enable mcui-xray-recover.service
```

开机只启用恢复 unit，由它按已提交状态决定是否启动 Xray。预检和 Xray unit 由本地事务调用。两个 Xray unit 使用不同的动态系统用户。项目自带限制适用于引导配置，包含独立网络命名空间、地址限制、内存和进程数限制以及对 Agent/Helper 状态的隔离。

## 2. 配置信任并安装

1. 通过独立渠道核对离线 TUF root 和指纹，将 root 以 `root:root`、`0444` 装入 root 管理的 `/etc/mcui-xray/root.json`。仓库角色分离、保管人和制品审核要求见[制品信任](./artifact-trust.md)。
2. 记录仓库 HTTPS metadata 地址、当前有效的 Xray 可审核 target、本机架构、版本和已审核 SHA-256。Xray 本地工具接受 `v主版本.次版本.补丁版本` 格式及有明确上游签名核验事实或无签名记录的已审核目标。面板目录里的 GitHub API digest 只用于发现及缓存校验。
3. 按[阶段 2 认证时间配置](./phase-2-operations.md#11-配置认证-nts-时间)配置并检查 chrony。TUF 未授权、时间异常、摘要不符或仓库刷新失败均会中止制品操作。

将环境变量填入已审核的具体值后执行。升级和降级的版本必须分别高于和低于已提交版本。节点原先已停止时仍会短暂检查候选进程，确认后恢复停止状态。

```sh
mcui-xray install -metadata-url "$TUF_METADATA_URL" -version "$VERSION" -sha256 "$SHA256"
mcui-xray status
systemctl show mcui-xray.service --property=ActiveState,SubState,MainPID

mcui-xray upgrade -metadata-url "$TUF_METADATA_URL" -version "$NEW_VERSION" -sha256 "$NEW_SHA256"
mcui-xray downgrade -metadata-url "$TUF_METADATA_URL" -version "$OLD_VERSION" -sha256 "$OLD_SHA256"
```

用 `status` 中已提交的版本和摘要填写以下命令。卸载停止服务并清理管理的已解包版本，保留事务状态、TUF 历史和压缩制品缓存。需要释放压缩缓存空间时，在确认没有本地事务运行后只清理 `/var/lib/mcui-xray/control/artifact-cache` 中的摘要文件。

```sh
mcui-xray stop -version "$CURRENT_VERSION" -sha256 "$CURRENT_SHA256"
mcui-xray start -version "$CURRENT_VERSION" -sha256 "$CURRENT_SHA256"
mcui-xray uninstall -version "$CURRENT_VERSION" -sha256 "$CURRENT_SHA256"
```

## 3. 处理未决事务

`mcui-xray status` 显示已提交版本、前一版本、运行意图、未决事务以及最近一次已完成的切换结果。实际进程状态以 systemd 为准。遇到 `ROLLBACK_FAILED`、断电或状态提交失败，先查看 `status` 和下列日志，再执行本地恢复。恢复未决事务时，工具会先停止候选，重验已提交的版本目录，再恢复已提交的运行状态。

```sh
journalctl -u mcui-xray.service -u mcui-xray-recover.service
mcui-xray status
mcui-xray recover
```

已提交目录或账本损坏时，停止 `mcui-xray.service`，保存 `/var/lib/mcui-xray` 和日志用于带外核验。恢复一致且可证明新鲜的状态前保持停止，避免重建空账本或手工改写版本指针。

## 4. Agent 和 Helper 本地人工修复

独立签名、自身更新监督、状态兼容验证与自动回滚仍待实现。已部署的 Agent 或 Helper 无法启动时，可使用部署前由独立渠道核验并留存的上一版二进制和配套 unit 进行带外修复。先确认旧版可读取目前账本、节点身份和协议版本。兼容性未知或账本已损坏时暂停，按阶段 2 的状态恢复流程核验。

1. 停止 `mcui-agent.service` 和 `mcui-helper.service`，保护并保存本地配置、信任材料、版本信息和两份状态目录。
2. 核对备份二进制和 unit 的审核记录及 SHA-256。将 `mcui-agent` 和 `mcui-helper` 安装为 `root:root`、`0755`，恢复对应 unit 与 drop-in，执行 `systemctl daemon-reload`。
3. 使用原节点参数和服务身份检查两份现有 ledger。启动 Helper，再启动 Agent。核对 Helper socket、面板心跳和一次只读状态查询结果。[阶段 2 操作说明](./phase-2-operations.md)
