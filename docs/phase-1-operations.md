# 主控与 Agent 接入运维

Agent 主动连接主控的 TLS 1.3 API，通过一次性安装码换取节点 Token。构建脚本打包 Linux amd64 和 arm64 的 Agent、只读状态 Helper 及其 systemd 单元。任务签名和 NTS 时间配置见[阶段 2 操作说明](./phase-2-operations.md)。

单管理员 Master 的 systemd、Compose、首次登录和 HTTPS 配置见[主控部署](./master-deployment.md)。

## 主控和批准的安装包

1. 为主控启用直连 TLS 或可信的 HTTPS 反代，确保节点可以访问配置的外部 HTTPS 地址。[HTTPS 接入](./master-deployment.md#https-接入)
2. 从经审核的提交构建安装程序，再通过批准的发布渠道发布。构建脚本输出安装程序的 SHA-256。通过独立可信渠道审核并取得发布清单中的 HTTPS 地址和摘要。
3. 将以下内容写入原生部署的 `/etc/mcui-master/panel.env`，然后重启面板。手工部署使用其现有环境文件。Compose 通过部署环境传入变量，用覆盖文件将公钥和可选 CA 只读挂载到容器中，变量中的路径须为容器内路径。

```sh
bash scripts/build-agent-installer.sh /tmp/mcui-agent-install.sh
```

```ini
MCUI_PUBLIC_URL=https://master.example.net:8443
MCUI_AGENT_INSTALLER_URL=https://releases.example.net/mcui/v1/mcui-agent-install.sh
MCUI_AGENT_INSTALLER_SHA256=<批准发布清单中的 SHA-256>
MCUI_AGENT_INSTALLER_TASK_KEY_ID=<状态任务签名 key ID>
MCUI_AGENT_INSTALLER_TASK_PUBLIC_KEY=/etc/mcui-master/task-signing.pub
# 私有 PKI 使用证书形式的 CA PEM。公有 CA 可省略此行。
MCUI_AGENT_INSTALLER_MASTER_CA=/etc/mcui-master/agent-trust-ca.pem
```

使用支持自动配置信任的新安装包时设置任务公钥及 key ID，两者须与启用的状态任务签发器一致。CA 文件只包含经核对的 CA 证书，大小上限为 16 KiB。发布下载使用节点系统 CA；可选的私有 CA 专用于验证 Master，Agent 仍校验证书链和主机名。

沿用旧安装包时仅设置安装包地址和摘要，并经可信渠道预置 `/etc/mcui-agent/task-signing.pub`、`/etc/mcui-agent/task-key-id` 及可选的 `/etc/mcui-agent/master-ca.pem`。目录使用 `root:root 0755`，信任文件使用 `root:root 0644`。

## 节点首次接入

1. 目标为运行 systemd 的 Linux amd64 或 arm64 节点。以 root 或有 sudo 权限的账号执行。在有 APT 的 Debian 系节点上，命令按需安装 curl、系统 CA 和缺失的基础工具。其他发行版使用本地包管理器准备依赖。使用任务查询前按阶段 2 说明配置 chrony。
2. 安全管理员在「节点管理」创建待接入的节点，选择「生成安装命令」并完成 MFA 复验。在 10 分钟内把命令粘贴到该节点的可信终端。命令先核验下载文件的 SHA-256，再以 root 运行安装程序。
3. 安装程序核对本地身份、Agent/Helper 账本和候选信任，再通过已验证的 HTTPS 兑换安装码。核对响应节点 ID 后，凭据原子写入 `/var/lib/mcui-agent/identity.json`（`0600`），安装程序补齐缺失的信任文件并启动服务。首次心跳使原记录上线，节点仍为空 Agent。

### 构建包含 Xray 引导的安装包

在构建机准备 Xray 安装任务公钥、制品发布公钥、已独立核对的生效清单 `manifest.json` 和原始签名 `manifest.json.sig`。安装任务、状态任务和发布使用各自的公钥。沿用原安装包地址与 SHA-256 审核流程，将生成的新包设置为主控批准的安装包。主控仍需启用已配置好的 Xray 签发及制品服务。

```sh
bash scripts/build-agent-installer.sh /tmp/mcui-agent-install.sh --xray-bootstrap \
  xray-install-key-1 xray-install.pub release.pub manifest.json manifest.json.sig
```

这个安装包在 Debian/systemd 节点执行同一条接入命令时，安装 Xray 管理单元、初始化 Agent 与 Helper 的制品清单状态，并准备本地 chrony NTS 时钟。节点上的状态任务和制品授权经 systemd 创建的 Unix 套接字读取经验证的时间。节点仍经主控安装所选的 Xray 版本。上游 NTS 未同步时签名任务等待可信时间。

在全新 amd64 节点上，该包还准备 iproute2、slirp4netns、入站凭据密钥和隔离网络服务。节点需支持 TUN、网络命名空间和 systemd 的地址过滤。保留状态的重新接入默认沿用原有配置模式。可按维护流程显式迁移旧节点。 [主控添加入站](./phase-4-xray-inbound.md#从主控添加入站) · [旧节点迁移](./phase-4-xray-inbound.md#将旧节点迁移到主控定义模式)

已启用 Xray 生命周期的节点重新接入时，需要保留 Agent 和 Helper 已接受的清单状态。状态丢失时接入命令会在兑换安装码前停止，按[制品信任恢复](./phase-3-release.md)核对并恢复原有状态。

### 首次接入时初始化成对更新

构建可信安装包时可同时传入 `--runtime-bootstrap` 和 `--xray-bootstrap`。前者使用已审核的 Agent/Helper 基线版本，以及彼此独立并区别于任务和 Core 签名的两个运行时公钥。

```sh
bash scripts/build-agent-installer.sh /tmp/mcui-agent-install.sh --runtime-bootstrap \
  v1.0.0 runtime-release.pub runtime-authorization.pub
```

首次接入时，安装器在兑换前校验公钥并初始化该节点的成对运行时，接入完成后由 systemd 启动同一版本指针下的 Agent 和 Helper。若接入中断，可使用同一安装包重试，监督器只接受与已初始化版本完全相同的二进制和信任。可用 `mcui-runtime status` 核对基线。远程领取需另行配置令牌并启用定时器。保留状态的重新接入沿用既有监督器配置。 [成对更新](./phase-3-runtime-update.md)

沿用原命令构建的安装包只准备 Agent 和 Helper。Xray 入站目录、业务网络配置和远程运行时监督的准备步骤当前分别见[受控入站部署](./phase-4-xray-inbound.md#节点准备)和[成对更新](./phase-3-runtime-update.md#启用本地监督)。

2026-11-24 在 `ro` 的 Debian 13 amd64 虚拟机验证 `75839cf`。虚拟机无外网网卡，使用隔离 HTTPS 注册端和 chrony 4.6.1 NTS 服务、独立测试 CA 与签名材料。执行一次安装命令后，Agent 和 Helper 启动，两份制品清单状态按预期属主写入，受限时钟套接字提供认证时间，Agent 回报 Xray 尚未安装的状态。重启后，已注册节点恢复心跳。该次演练的覆盖范围是 Agent 接入和 Xray 生命周期引导。

生成、替换和撤销只操作所选节点。安装命令包含一次性安装码，应通过可信途径交付，避免写入共享终端历史、工单和日志。长期 Token 只由 Agent 从 HTTPS 响应取得。安装码兑换响应丢失或凭据保存失败时，为原节点生成新命令。

### 一键接入验证

2026-11-21，在 `ro` 的隔离检出验证 `da7479d`。完整静态检查、Master、Agent、Helper 与 `internal/security` 的定向竞态测试，以及 amd64/arm64 安装包构建通过。在干净 Debian amd64 容器使用测试发布证书和独立的私有 Master CA 执行面板命令。验证篡改安装包和错误 CA 被拒绝，修正后可用原命令重试。由真实 Master、Agent 和 Helper 验证首次心跳，并对包内 systemd 单元运行静态校验。另在移除 curl 的容器中验证命令通过 APT 补齐依赖后完成接入。

原节点补发命令验证了已有 PEM 公钥兼容、拒绝变更既有公钥或 CA、复用两份账本、旧 Token 在新凭据兑换后失效，以及已使用安装码不能再次兑换。

## 轮换、禁用与旧节点迁移

- 轮换时为原节点补发命令。补发作废之前未兑换的码，成功兑换立即作废原 Token。禁用节点会同时撤销 Token 和未兑换的安装码，并终止新的任务签发和投递。
- 安装命令沿用相同的已有任务公钥、key ID 和 CA。已有文件与命令携带的信任不一致时会在兑换前中止。更换密钥或 CA 使用本地受保护的信任轮换流程，再为原节点补发命令。
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

数据库、节点撤销状态、管理员凭据和审计均属敏感数据。备份须放在受访问控制和静态加密保护的存储上，并有独立权限与保留计划。`mcuidb` 提供一致性和结构验证。恢复前停止主控，按单机流程核对两库、撤销与账本。启用独立检查点时，还须核对检查点的新鲜度。状态连续性无法确认时暂停恢复线上数据库、节点注册和轮换。[单机及独立检查点恢复](./phase-2-operations.md#8-部署独立检查点)
