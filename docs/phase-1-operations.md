# 主控与 Agent 接入运维

Agent 主动连接主控的 TLS 1.3 API，通过一次性安装码换取节点 Token。安装包包含 Linux amd64 和 arm64 的 Agent、只读状态 Helper 及其 systemd 单元。任务签名和 NTS 时间配置见[阶段 2 操作说明](./phase-2-operations.md)。

## 主控和批准的安装包

1. 为主控配置完整的 HTTPS 证书链和匹配的服务端私钥。示例 [mcui-panel.service](../deploy/systemd/mcui-panel.service) 使用专用 `mcui` 账号，私钥应由该账号独占读取（`0600`）。
2. 从经审核的提交构建安装程序，再通过批准的发布渠道发布。构建脚本输出安装程序的 SHA-256。通过独立可信渠道审核并取得发布清单中的 HTTPS 地址和摘要。
3. 将以下内容写入主控的 `/etc/mcui/panel.env`，然后重启面板。也可使用同名功能的 `-public-url`、`-agent-installer-url` 和 `-agent-installer-sha256` 参数。

```sh
bash scripts/build-agent-installer.sh /tmp/mcui-agent-install.sh
```

```ini
MCUI_PUBLIC_URL=https://master.example.net:8443
MCUI_AGENT_INSTALLER_URL=https://releases.example.net/mcui/v1/mcui-agent-install.sh
MCUI_AGENT_INSTALLER_SHA256=<批准发布清单中的 SHA-256>
```

主控直接提供 HTTPS；Agent 会校验证书链和主机名。面板使用显式配置的主控地址和批准制品信息生成命令。部署时可通过既有本地方式使用 `MCUI_BOOTSTRAP_TOKEN` 初始化安全管理员。

## 节点首次接入

1. 在目标 Linux 节点准备 systemd、CA 证书、curl、sudo 和基本 GNU 工具。Debian 可安装 `ca-certificates curl sudo passwd util-linux coreutils tar gzip`。使用任务查询前按阶段 2 说明配置 chrony。
2. 经独立可信渠道分发任务签名公钥和对应 key ID 至 `/etc/mcui-agent/task-signing.pub` 与 `/etc/mcui-agent/task-key-id`（单行文本）。目录应为 `root:root 0755`，公钥文件应为 `root:root 0644`。公有 CA 证书使用系统信任库。私有证书部署通过可信渠道将 CA 放在 `/etc/mcui-agent/master-ca.pem`（`root:root 0644`），供 Agent 与 Helper 使用。
3. 安全管理员在「节点管理」填写名称和分组，创建待接入的节点。选择「生成安装命令」，按提示完成 MFA 复验。在 10 分钟内把命令粘贴到该节点的可信终端。命令会在提权执行安装程序前校验下载文件的 SHA-256。
4. 安装程序核对本地节点身份，验证或初始化 Agent/Helper 账本，兑换安装码并核对响应节点 ID。凭据原子写入 `/var/lib/mcui-agent/identity.json`（`0600`）。服务启动后刷新面板，首次心跳会使原记录上线。在干净节点上三种 Core 均未安装。

生成、替换和撤销只操作所选节点。安装命令包含一次性安装码，应通过可信途径交付，避免写入共享终端历史、工单和日志。长期 Token 只由 Agent 从 HTTPS 响应取得。安装码兑换响应丢失或凭据保存失败时，为原节点生成新命令。

## 轮换、禁用与旧节点迁移

- 轮换时为原节点补发命令。补发作废之前未兑换的码，成功兑换立即作废原 Token。禁用节点会同时撤销 Token 和未兑换的安装码，并终止新的任务签发和投递。
- 升级前保护性备份 Master 数据库和任务库，并保留节点上的原 Agent 身份、Agent 账本与 Helper 账本。升级面板时更新 systemd unit 和任务 drop-in，移除旧的 `-node-ca-cert`、`-node-ca-key`。Master schema 迁移保留节点 ID 和管理数据，升级后旧 mTLS Agent 会暂停通信，直至用原节点的命令兑换 Token。
- 检查原先使用自定义路径的部署。安装程序预期 Agent 状态在 `/var/lib/mcui-agent`，Helper 状态在 `/var/lib/mcui-helper`。先以原有权限和属主恢复至这些位置，保留账本、WAL 和快照的一致性。安装程序验证两份原账本，继续沿用原节点 ID 和序号。
- 原节点缺少任一账本时，先冻结任务并核对主控历史。只有能证实该组件从未处理任务时，才按经确认的本地初始化流程创建对应账本。原 Agent 可用 `-initialize-task-ledger`，Helper 可用 `-initialize-ledger`，参数示例见[阶段 2 操作说明](./phase-2-operations.md)。存在不确定历史时按[Agent 协议恢复规则](./agent-protocol.md#6-防回退与灾难恢复)处理。
- 可使用 `journalctl -u mcui-agent -u mcui-helper` 检查安装后服务状态，并从主控发起一条只读状态任务验证租约和 ACK。

## SQLite 备份与恢复候选

`mcuidb` 对在线 SQLite 数据库执行 `VACUUM INTO` 一致性快照，输出新文件、设为仅所有者可读写并运行 `PRAGMA integrity_check`。恢复命令只生成新路径的候选文件，不覆盖当前数据库：

```sh
install -d -o mcui -g mcui -m 0700 /var/lib/mcui/backups
sudo -u mcui /usr/local/bin/mcuidb backup -db /var/lib/mcui/mcui.db -out /var/lib/mcui/backups/snapshot.db
/usr/local/bin/mcuidb verify -db /var/lib/mcui/backups/snapshot.db
/usr/local/bin/mcuidb restore -backup /var/lib/mcui/backups/snapshot.db -out /var/lib/mcui/restore-candidate.db
/usr/local/bin/mcuidb verify -db /var/lib/mcui/restore-candidate.db
```

数据库、节点撤销状态、管理员凭据和审计均属敏感数据。备份必须放在受访问控制和静态加密保护的存储上，并有独立权限与保留计划；`mcuidb` 不加密备份，也不提供防篡改/新鲜度证明。恢复旧数据可能复活当时尚未记录的撤销、凭据或管理员变更。必须先停服并用独立可信检查点核对新鲜度；无法证明状态连续时，不得把候选文件放到线上路径或恢复节点注册/轮换。候选文件的完整性通过不等于恢复获准。
