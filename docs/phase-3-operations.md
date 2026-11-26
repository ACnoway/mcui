# 阶段 3 Xray 本地生命周期

远程安装的授权、签发及旧流程迁移见 [Xray 安装的运维授权与独立签发](./phase-3-approval.md)。

以下步骤从固定的官方 GitHub Releases 获取 Xray。安装时在管理面板选择该节点架构可用的稳定版本；Agent 和 Helper 根据签名任务中的版本、架构和摘要校验下载制品。[发布说明](./phase-3-release.md)

`mcui-xray` 在 Linux amd64/arm64 节点上由本地 root 管理独立的 `mcui-xray.service`。默认用固定空 JSON 引导配置启动，受控入站另行启用。远程安装和配置通过同一套生命周期事务应用。指定版本和架构的产品状态见[能力矩阵](./core-compatibility.md)和[受控入站部署](./phase-4-xray-inbound.md)。

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

## 2. 选择版本并安装

面板的「管理 Core」抽屉会显示该节点架构对应的已发布稳定版本。选择安装、升级或降级目标后，Master 将确切版本、架构和 SHA-256 写入签名任务；Agent 和 Helper 使用固定的 Xray 官方 Release 地址下载，并在安装前核对大小和 SHA-256。上游没有公布 SHA-256 时，Master 下载官方制品计算摘要再签入任务。节点无需安装 Core 发布公钥、清单或清单状态。

在单机使用 `mcui-xray` 时，先从 Xray 官方 Release 核对版本、架构、文件名和 SHA-256，再执行下列命令。升级和降级目标必须分别高于和低于已提交版本。节点原先已停止时仍会短暂检查候选进程，确认后恢复停止状态。远程任务仍需配置[认证时间](./phase-2-operations.md#11-配置认证-nts-时间)。

```sh
mcui-xray install -version "$VERSION" -sha256 "$SHA256"
mcui-xray status
systemctl show mcui-xray.service --property=ActiveState,SubState,MainPID

mcui-xray upgrade -version "$NEW_VERSION" -sha256 "$NEW_SHA256"
mcui-xray downgrade -version "$OLD_VERSION" -sha256 "$OLD_SHA256"
```

用 `status` 中已提交的版本和摘要填写以下命令。卸载停止服务并清理管理的已解包版本，同时保留事务状态和压缩制品缓存。需要释放空间时，在确认没有安装事务运行后清理 `/var/lib/mcui-xray/control/artifacts` 中的缓存文件。

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

恢复旧备份时，先暂停新制品操作并保存故障前后的状态目录与日志。恢复后核对 `mcui-xray status`、当前官方 Release 和已部署二进制的 SHA-256；不确定状态时不要重建空账本或手工改写版本指针。Core 安装不维护独立发布公钥或单调递增的清单状态。

### 进程中断恢复验收

1. 在隔离节点运行一个已提交版本，记录摘要、运行意图及 systemd 状态。
2. 开始一次版本切换。在事务意图及候选切换已落盘、提交候选前，对事务进程发送 `SIGKILL`。
3. 重新启动恢复流程。Xray 可执行 `mcui-xray recover`，或通过 systemd 启动 `mcui-xray-recover.service`。确认最后一次成功提交的版本、摘要和运行状态恢复，未决事务清除。重复运行恢复入口应得到相同状态。

本地 Xray 已通过切指针后中断和恢复。Agent/Helper 的同类测试通过其成对启动监督入口执行，核对原来的两个服务、账本与节点身份。[成对更新](./phase-3-runtime-update.md) · [已执行检查](./phase-3-progress.md#已执行检查)

## 4. Agent 和 Helper 本地人工修复

已纳入成对监督的节点使用 `mcui-runtime repair` 恢复中断事务，或按[成对更新手册](./phase-3-runtime-update.md#启动检查与回退)试运行上一次提交的版本。沿用原部署的 Agent 或 Helper 无法启动时，可使用部署前由独立渠道核验并留存的上一版二进制和配套 unit 进行带外修复。先确认旧版可读取目前账本、节点身份和协议版本。兼容性未知或账本已损坏时暂停，按阶段 2 的状态恢复流程核验。

1. 停止 `mcui-agent.service` 和 `mcui-helper.service`，保护并保存本地配置、信任材料、版本信息和两份状态目录。
2. 核对备份二进制和 unit 的审核记录及 SHA-256。将 `mcui-agent` 和 `mcui-helper` 安装为 `root:root`、`0755`，恢复对应 unit 与 drop-in，执行 `systemctl daemon-reload`。
3. 使用原节点参数和服务身份检查两份现有 ledger。启动 Helper，再启动 Agent。核对 Helper socket、面板心跳和一次只读状态查询结果。[阶段 2 操作说明](./phase-2-operations.md)

## 5. 启用远程 Xray 安装

在已接入阶段 2 任务运行时的节点上，先按第 1、2 节安装并初始化 Xray 单元。Xray bootstrap 安装包会将 `mcui-manifest` 时钟辅助程序部署到 `/usr/local/bin/mcui-manifest`；`mcui-node-clock@.service` 通过它读取 chrony NTS 认证时间，Agent 和 Helper 再经 Unix 套接字获取时间。主控启用 HTTPS、Cloudflare NTS 认证时间及运维授权策略。单机部署可省略独立检查点。Agent 和 Helper 读取 root 管理的 Xray 安装任务公钥，分别验签并校验官方制品摘要。直连官方源不可用时，两个服务可凭当前签名任务和有效租约向 Master 请求精确匹配的缓存。[单机备份恢复](./phase-2-operations.md#单机运行与备份恢复)

将以下配置作为 root 管理的 `/etc/mcui-agent/xray-install.env`，按可信发布材料替换实际值：

```ini
MCUI_XRAY_INSTALL_KEY_ID=xray-install-key-1
MCUI_XRAY_INSTALL_PUBLIC_KEY=/etc/mcui-agent/xray-install.pub
```

仅需部署 Xray 生命周期任务公钥与 key ID。新节点不需 Core 发布公钥、签名清单或 TUF 状态；已有旧 TUF 配置可从新部署配置中移除。

使用更新后的 Agent 任务运行时 drop-in。将 `deploy/systemd/mcui-helper-xray-install.conf` 安装到 `mcui-helper.service.d/`，然后重载单元并重新启动 Agent 与 Helper。该 drop-in 为 Helper 开放固定的 Xray 运行目录。Master、Agent 和 Helper 均通过 [受控 loopback 监控接口](./phase-2-operations.md#11-配置认证-nts-时间)读取认证时间。本地 root 工具继续使用 chrony Unix 套接字。

单管理员在节点列表打开「管理 Core」，选择安装和经过核验的版本，经面板授权及 MFA 检查，由后台独立签发并投递。手工授权部署由原发起运维员在抽屉内的「独立签发提案」上传签名请求和任务后投递。两种流程均可在抽屉内刷新结果。Agent 可以每 15 秒续订当前 60 秒租约。Helper 在候选预检和激活前重新向主控校验租约和范围，并以本地可信时间约束任务期限。`FAILED` 表示激活前退出，`ROLLED_BACK` 表示已恢复，`NEEDS_RECONCILIATION` 在面板显示为「待对账」，后续序号暂时阻塞。[签发配置](./phase-3-approval.md)

### 远程安装对账

1. Master、Agent、Helper 和节点端 `mcui-xray` 使用支持对账的同版构建。节点替换 Helper 与本地工具时一起部署，确保两者均能读取含安装事务凭证的状态文件。保留现有状态目录和账本。
2. 安装被中断后，等待 Agent 重新轮询，在「管理 Core」抽屉或「设置 → 任务」刷新任务结果。Helper 核对原签名任务、节点、序号和信封摘要。已有完成记录时直接返回。若激活事务仍未决且能绑定原任务，Helper 恢复上次提交状态，再记录回滚完成。开机恢复也会保留相同凭证。
3. Agent 先保存结果，再向 Master 补报 `SUCCEEDED` 或 `ROLLED_BACK`。原任务过期后仍能补报。待对账投递不会续发安装租约，也不会下载制品或开始新的安装。Master 收到终态后开放下一序号。
4. 一直待对账时，按第 3 节检查节点本地状态并保留 Master、Agent、Helper 账本和 Xray 状态目录。旧版未决记录可能没有签名任务凭证。凭证缺失、不匹配或回滚仍失败时保留阻塞，供运维核验。

## 6. 远程启停

1. 在已启用远程 Xray 的测试节点部署支持启停的 Master、签发工具、Agent、Helper 和节点端 `mcui-xray`。Helper 和本地工具需同时支持启停事务凭证。旧 Agent 不会领取启停任务。
2. 在节点列表的「管理 Core」抽屉中选择「启动」或「停止」。单管理员面板从节点心跳读取已提交的版本、架构和 SHA-256。手工签发流程需要用 `mcui-xray status` 核对该版本与摘要并填写提案。[授权与签发](./phase-3-approval.md)
3. 在抽屉内刷新状态和任务。启动确认 `mcui-xray.service` 持续运行及主 PID 稳定，停止确认服务处于 `inactive/dead` 且主 PID 为 0。Helper 用同一租约复验精确目标，只控制固定服务。启停使用节点现有制品。
4. 中断时沿用远程安装的对账规则。已提交或已回滚的原任务可补报，证据不足时保留待对账。停止会改变持久化运行意图，节点开机恢复后仍保持停止。

## 7. 远程版本切换与卸载

1. 在已启用远程 Xray 的测试节点部署支持版本切换和卸载的 Master、签发工具、Agent、Helper 和本地 `mcui-xray`。
2. 升级或降级前，用 `mcui-xray status` 核对已安装版本和 SHA-256。面板只列出该节点架构有对应资产的官方稳定版本，并在任务中绑定当前和目标版本。升级要求目标更高，降级要求目标更低。
3. 单管理员面板从官方发布目录选目标版本并请求后台签发。卸载绑定节点已提交的版本和摘要。降级与卸载须分别确认并提供当前 MFA。[授权与签发](./phase-3-approval.md)
4. 刷新面板结果。升级或降级先预检候选，再按原运行意图提交切换。候选启动失败时，Helper 停止候选，清除已无主进程的 unit 失败状态，并恢复上一可用版本和运行意图。卸载确认服务已停止并清理受管版本，保留账本和制品缓存。任务待对账时按第 3 节核验节点状态。
