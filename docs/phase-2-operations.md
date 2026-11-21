# 阶段 2 状态任务部署说明

本文只描述当前实现的 V2 `core.status` 查询。它不能签发 Core 安装、启动/停止、配置、任意命令或其他会改变系统的任务；也不构成生产密钥托管或阶段验收批准。当前运行限制与未完成项见[阶段 2 进度](./phase-2-progress.md)。

## 1. 组件和权限

| 组件 | 账号/接口 | 持有材料 |
|---|---|---|
| Master | `mcui`；TLS 1.3 API | task 数据库、状态签名公钥、仅供 loopback signer 使用的共享 token |
| Signer | 独立 `mcui-signer`；仅监听 `127.0.0.1:9231` | 状态任务 Ed25519 私钥、共享 token；签名 API 只接受 V2 状态任务 |
| Agent | 非 root `mcui-agent`；出站 HTTPS、节点 Token | Master CA、状态签名公钥、Agent 身份和私有任务账本；无任务签名私钥 |
| Helper | root；`/run/mcui/helper.sock` | 状态签名公钥、Master CA、root 私有账本；只可连接 Master checkpoint 和读取固定 systemd 属性 |

生产密钥必须由经批准的独立流程产生、保管、备份和轮换。不要使用测试向量 seed。Signer 私钥不得复制给 Master、Agent 或 Helper；只分发状态签名公钥。Signer token 至少 32 字节随机值，只用于两个本机账号之间的 HTTP bearer 认证。

### 1.1 配置认证 NTS 时间

Master、Agent 和 Helper 的任务时限判断依赖本机 chrony。选用 Cloudflare 官方 NTS 服务 `time.cloudflare.com`；NTS 通过 TLS 建立密钥，并认证 NTP 时间包。应用只接受它被 chrony 选为当前来源且 `authdata` 证明 NTS 正在工作，不会因 NTS 失败改用未认证来源。

安装并配置 chrony。下方 UDP 监控配置要求 chronyd 支持 `opencommands`。Debian 13.7 的 chrony 4.6.1 会拒绝该指令，且默认 UDP 端口拒绝 `authdata`。这种部署下，面板和节点任务服务仍须提供受控的只读认证时间接口；已有权限的本地操作员可通过 `/run/chrony/chronyd.sock` 核对状态。

使用支持 `opencommands` 的版本时，修改 `/etc/chrony/chrony.conf`，确认未认证的 `pool`/`server` 源退出选择，保留本机 loopback command socket。

```conf
server time.cloudflare.com iburst nts
opencommands authdata sources tracking
```

不要把 chrony command socket 绑定到外部接口，也不要添加宽泛的 `cmdallow`。`opencommands` 仅开放应用需要的只读监控命令；chronyd 默认只监听 loopback 命令地址。重启服务后，以 root 检查：

```sh
systemctl enable --now chrony
chronyc -h 127.0.0.1 -N sources
chronyc -h 127.0.0.1 -N authdata
chronyc -h 127.0.0.1 -N tracking
```

确认 `sources` 的 `*` 行为 `time.cloudflare.com`，`authdata` 的同一行显示 `NTS`、AEAD 类型和非零 cookie，tracking 的 `Leap status` 为 `Normal`。程序要求最近有效样本不超过 300 秒，系统时钟误差界限不超过 1 秒；否则状态任务创建、投递、执行及 ACK 会暂停并失败关闭。Agent 和 Helper 还要求与 TLS Master 时间相差不超过 30 秒。不同 chrony 版本若输出格式不兼容也会失败关闭。

## 2. 安装账号、程序和 unit

在已有阶段 1 系统安装 `mcui`、`mcui-agent` 用户后，创建本地 signer 账号和共享访问组，并授予 Master 与 signer 读取 token 的组权限：

```sh
groupadd --system mcui-task
useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid mcui-task mcui-signer
usermod -a -G mcui-task mcui
install -d -o root -g mcui-task -m 0750 /etc/mcui-task-signer
install -d -o root -g root -m 0755 /etc/systemd/system/mcui-panel.service.d
install -d -o root -g root -m 0755 /etc/systemd/system/mcui-agent.service.d
install -o root -g root -m 0755 mcui-helper /usr/local/bin/mcui-helper
install -o root -g root -m 0755 mcui-signerd /usr/local/bin/mcui-signerd
install -o root -g root -m 0644 deploy/systemd/mcui-helper.service /etc/systemd/system/
install -o root -g root -m 0644 deploy/systemd/mcui-signerd.service /etc/systemd/system/
install -o root -g root -m 0644 deploy/systemd/mcui-panel-task-runtime.conf /etc/systemd/system/mcui-panel.service.d/phase2.conf
install -o root -g root -m 0644 deploy/systemd/mcui-agent-task-runtime.conf /etc/systemd/system/mcui-agent.service.d/phase2.conf
```

确保前端静态文件与 Master 二进制已按[阶段 1 操作说明](./phase-1-operations.md)安装。task-runtime drop-in 会替换基础 `ExecStart` 并开启 Master 任务 API；Agent drop-in 会开启任务轮询。不要在尚未准备签名公钥、私有账本和 Helper 服务时启用它们。

## 3. 分发信任材料和写入服务配置

经可信渠道将同一把 task 公钥装到 Master 和目标节点：

```text
/etc/mcui/task-signing.pub                 Master 读取，0644 root:root
/etc/mcui-task-signer/task-key.pem         Signer 读取，0600 mcui-signer:mcui-signer
/etc/mcui-task-signer/token               Master 和 Signer 读取，0640 root:mcui-task
/etc/mcui-agent/task-signing.pub          Agent 与 Helper 读取，0644 root:root
/etc/mcui-agent/master-ca.pem             私有 CA 部署时提供，0644 root:root
```

`task-key.pem` 必须是 PKCS#8 Ed25519 PEM；公钥文件可用 PKIX PEM 或 Base64 编码的 32 字节 raw key。Signer token 文件至少 32 字节；它不可由其他用户或组写入。Master 账号通过 `mcui-task` 补充组读取 token；Helper 和 Agent 不读取该 token。

通过受限的 root 配置管理写入以下仅含非秘密配置值的环境文件，模式 `0640 root:<对应服务组>`，且不得让服务账号写入：

```text
/etc/mcui-task-signer/signer.env: MCUI_TASK_KEY_ID=<已分发公钥对应的 key ID>
/etc/mcui/panel-task-runtime.env: MCUI_TASK_KEY_ID=<同一个 key ID>
/etc/mcui-agent/agent-task-runtime.env: MCUI_TASK_KEY_ID=<同一个 key ID>
/etc/mcui-agent/helper.env:
  MCUI_NODE_ID=<面板中已注册节点的 node ID>
  MCUI_MASTER_URL=https://<Master DNS 名>:8443
  MCUI_TASK_KEY_ID=<同一个 key ID>
```

Agent 和 Helper 的运行配置由安装程序写入。手工部署时，`agent.env` 和 `helper.env` 需设置相同的 `MCUI_MASTER_URL`、`MCUI_NODE_ID` 和可选的 `MCUI_SERVER_CA`。Helper 的 Master URL 必须是 HTTPS origin，不包含路径、query、用户信息或片段；主机名必须与 Master 证书匹配。

## 4. 为已有节点显式初始化本地账本

安装程序在新节点首次兑换安装码前创建两份账本，迁移时则验证已有账本。对已有阶段 1 节点启用阶段 2 前，先确认 Master 任务历史为空，停止 Agent，并用现有 Master 和节点参数只运行一次：

```sh
systemctl stop mcui-agent.service
sudo -u mcui-agent /usr/local/bin/mcui-agent \
  -master https://master.example.net:8443 \
  -node-id "$MCUI_NODE_ID" \
  -server-ca /etc/mcui-agent/master-ca.pem \
  -initialize-task-ledger \
  -task-ledger /var/lib/mcui-agent/tasks.db
```

该命令只在节点已有注册身份、账本不存在且状态目录权限正确时创建新账本；如果文件已存在即失败。它不会尝试修复、覆盖或重建已有数据库。若 Master 已存在此节点任务、Agent 账本曾丢失/回滚或历史不明，停止并走带外恢复，不要初始化空账本来绕过序号。

Helper 账本初始化仅可在目标节点身份和 key ID 核对后执行一次。先确认 Helper 未运行，并以 root 读取可信配置：

```sh
set -a
. /etc/mcui-agent/helper.env
set +a
/usr/local/bin/mcui-helper \
  -node-id "$MCUI_NODE_ID" -master "$MCUI_MASTER_URL" \
  -master-ca="${MCUI_SERVER_CA:-}" \
  -task-key-id "$MCUI_TASK_KEY_ID" \
  -task-public-key /etc/mcui-agent/task-signing.pub \
  -state-dir /var/lib/mcui-helper -initialize-ledger
unset MCUI_NODE_ID MCUI_MASTER_URL MCUI_TASK_KEY_ID
chown root:mcui-agent /var/lib/mcui-helper
```

`-initialize-ledger` 只创建新 ledger，不恢复缺失或损坏状态。现有 Helper 账本、软链接、非 `0700` 目录、非 `0600` 数据文件或不匹配节点身份都会导致拒绝。若命令不是首次初始化并返回文件已存在，应停在此处调查，不要删除账本。

## 5. 检查并启动

```sh
systemd-analyze verify \
  mcui-panel.service mcui-agent.service \
  mcui-helper.service mcui-signerd.service
systemctl daemon-reload
systemctl enable --now mcui-signerd.service mcui-helper.service
systemctl restart mcui-panel.service mcui-agent.service
```

先确认 signer 仅监听 loopback、token/key 文件权限符合预期、Helper socket 是 root 拥有且组为 `mcui-agent` 的 `0660` Unix socket、父目录为 root 拥有的 `0750`，再登录面板发起一条只读状态查询。查看任务 ACK 和审计记录；不要以没有安装某个 Core 来推断服务状态为 `active`，此时预期状态通常是 `not-found`。

## 6. 恢复与故障处理

- Master signer 不可用或配置错误时，任务不会签发入队；查看 `mcui-signerd` 和 Master 日志。不要将私钥临时复制到 Master。
- 60 秒投递租约到期后，Master 可为同一消息签发新租约；Helper 只接受当前租约。先前成功查询从 Helper 账本返回原结果，不再执行 `systemctl`。
- Agent 收到过期消息时只持久化并回报 `EXPIRED`，不调用 Helper。节点离线期间，未完成序号会继续阻塞该节点后续任务；节点重新上线处理过期任务后才可继续。
- 面板可取消未过期且未开始的状态查询；若任务已经开始或状态未决，Agent 账本会拒绝取消并回报现有状态/对账要求。过期状态任务可通过签名 `EXPIRED` skip 确认终态，Agent 仍先将原始任务写为过期，不调用 Helper。面板上的控制状态可刷新查看。
- Agent 账本重启时发现执行中状态会进入 `NEEDS_RECONCILIATION`；Helper 存在未决记录、Master 无法确认前序序号终态或本地账本不匹配时不继续。Master 只自动补取可证明的、已过期终态历史槽，或投递已签名 `VOID_UNISSUED` 空槽；未知、活动、未过期或运行中缺口继续隔离。过期历史只补齐 Agent 序号，不恢复原任务结果。Master 启动时会对账任务与审计库，并修复已持久化签发/关闭但因崩溃缺失的后置审计。
- 保留原始 SQLite 文件及诊断日志，使用向前一致的备份恢复。配置独立检查点的主控会拒绝与最新检查点不一致的数据库；见下方的恢复步骤。NTS 配置失效时按 1.1 节修复认证时间源。

## 7. 当前限制

任务运行时目前支持只读状态查询、pending cancel、expired skip、过期终态补取和 `VOID_UNISSUED` 空槽关闭。通用 `CANCELED` skip、跨数据库原子恢复、硬件可信时间根、密钥轮换仪式和 Agent/Helper 故障演练仍待完成。独立检查点须显式配置，受保护模式只支持单 Linux 主控进程，数据 API 串行核对两库逻辑摘要。旧 Master 任务库启动时会在严格校验后增建控制表；升级前保留受保护备份。

## 8. 部署独立检查点

单机自用可以省略 `MCUI_TASK_CHECKPOINT_*` 和对应命令行参数。需要检测 Master 的两份数据库被整体恢复到旧版本时，再按本节部署独立检查点。无论采用哪种方式，节点的 Helper 都通过 Master 自身的 HTTPS 接口在线核验当前租约。

### 单机运行与备份恢复

单机 Master 继续用 Cloudflare NTS、任务验签、节点账本和两库启动对账。停 Master 后同时备份面板库 `mcui.db` 与任务库 `tasks.db`。如果 Xray 签发账本也在这台机器上，保存它的最新副本并单独管理，避免恢复 Master 快照时覆盖账本。保留 Agent、Helper 和成对更新监督器各自的当前状态。

没有外部记录时，主控无法可靠检测两库一起恢复成较早但彼此一致的版本。恢复时先停用远程派发，核对恢复候选、签发账本与存活节点上的任务序号、未决操作和运行时版本。对无法确认是否已经执行的任务，先核对节点实际状态和账本，再恢复远程操作。单节点可按操作手册进行本地修复。

### 独立检查点配置

`mcui-checkpointd` 为一个检查点身份和 epoch 持久化最新 revision 与 SHA-256，提供读取和比较后更新两个接口。服务使用 TLS 1.3 验证客户端签发链，并核对其公钥 SPKI 的 SHA-256 指纹。主控用指定 CA 验证服务端证书和主机名，每次请求绑定新的随机挑战。

1. 在验证环境构建 `go build -trimpath -o mcui-checkpointd ./cmd/mcui-checkpointd`。将二进制和 `deploy/systemd/mcui-checkpointd.service` 安装到独立检查点主机，创建专用系统账号和组 `mcui-checkpoint`。
2. 在 `/etc/mcui-checkpoint` 部署服务端证书链 `server-chain.pem`、私钥 `server-key.pem`、客户端专用 CA `client-ca.pem`。目录由 root 管理，服务账号只读；私钥使用 `root:mcui-checkpoint 0640`。在 `checkpoint.env` 写入 `MCUI_CHECKPOINT_LISTEN`（管理网络的监听地址和端口）及 `MCUI_CHECKPOINT_CLIENT_KEY_SHA256`（已批准客户端 SPKI 的 64 位十六进制 SHA-256）。将服务端 CA 通过独立渠道交给客户端。
3. 在首次启用检查点前，核验主控任务库、面板库及撤销状态的新鲜度，停止主控并备份两库。由主控服务账号在私有目录生成新 journal，记下命令输出的初始摘要。

   ```sh
   mcui-checkpointd init-master-journal -db /var/lib/mcui/mcui.db \
     -task-db /var/lib/mcui/tasks.db -journal /var/lib/mcui/task-checkpoint.db \
     -node "$IDENTITY" -epoch "$EPOCH"
   ```

4. 通过独立渠道将身份、epoch 和初始摘要交给检查点保管人。首次引导时创建 `mcui-checkpoint:mcui-checkpoint 0700` 的 `/var/lib/mcui-checkpoint`，以服务账号执行 `mcui-checkpointd init -db /var/lib/mcui-checkpoint/authority.db -node "$IDENTITY" -epoch "$EPOCH" -sha256 "$DIGEST"`。执行 `systemctl daemon-reload` 和 `systemctl start mcui-checkpointd.service`。该数据库由独立账号和主机管理，须置于主控的备份回滚域之外。两个初始化命令都只创建新文件。
5. 在 `/etc/mcui/panel-task-runtime.env` 添加以下配置。主控客户端私钥由 `mcui` 账号以 `0600` 读取，服务端 CA 和客户端证书使用已核验的 PEM 文件。启用后保持这组配置与两库和 journal 一同纳入部署审计。

   ```dotenv
   MCUI_TASK_CHECKPOINT_URL=https://checkpoint.example.net:9232
   MCUI_TASK_CHECKPOINT_JOURNAL=/var/lib/mcui/task-checkpoint.db
   MCUI_TASK_CHECKPOINT_CA=/etc/mcui/checkpoint-server-ca.pem
   MCUI_TASK_CHECKPOINT_CLIENT_CERT=/etc/mcui/checkpoint-client.pem
   MCUI_TASK_CHECKPOINT_CLIENT_KEY=/etc/mcui/checkpoint-client-key.pem
   ```

6. 启动主控并确认任务查询和节点心跳可用。每个数据 API 在处理前核对面板库和任务库的逻辑摘要及远端 revision。摘要包含任务、租约、控制、ACK、账号、凭据、会话和审计，排除节点心跳更新时间。变更提交后先写入本地 intent 并更新独立检查点，再回传任务、租约、凭据或成功结果。运行时校验失败返回 `503`。配置错误或启动对账失败时主控拒绝启动。

### 协调备份和恢复

停主控后将两库与本地 journal 一起做受保护快照。启动时同时核对真实数据库摘要、本地 journal 和独立端；同一时点的旧两库即使能互相对账，仍会因摘要或 revision 落后被拒绝。保留的 intent 只有在真实摘要匹配其目标记录、独立端处于原 revision 或目标 revision 时才自动完成。若进程在数据库提交后、intent 落盘前中断，可能需要带外人工对账。保留原文件并冻结 API，由保管方核对最新独立端记录与候选恢复数据。现有 `/healthz` 检查的是进程存活，验证任务可用性需观察已认证的数据 API 和主控日志。
