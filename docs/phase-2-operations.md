# 阶段 2 状态任务部署说明

本文只描述当前实现的 V2 `core.status` 查询。它不能签发 Core 安装、启动/停止、配置、任意命令或其他会改变系统的任务；也不构成生产密钥托管或阶段验收批准。当前运行限制与未完成项见[阶段 2 进度](./phase-2-progress.md)。

## 1. 组件和权限

| 组件 | 账号/接口 | 持有材料 |
|---|---|---|
| Master | `mcui`；现有 TLS 1.3/mTLS API | task 数据库、状态签名公钥、仅供 loopback signer 使用的共享 token |
| Signer | 独立 `mcui-signer`；仅监听 `127.0.0.1:9231` | 状态任务 Ed25519 私钥、共享 token；签名 API 只接受 V2 状态任务 |
| Agent | 非 root `mcui-agent`；出站 HTTPS/mTLS | Master CA、状态签名公钥、Agent 身份和私有任务账本；无任务签名私钥 |
| Helper | root；`/run/mcui/helper.sock` | 状态签名公钥、Master CA、root 私有账本；只可连接 Master checkpoint 和读取固定 systemd 属性 |

生产密钥必须由经批准的独立流程产生、保管、备份和轮换。不要使用测试向量 seed。Signer 私钥不得复制给 Master、Agent 或 Helper；只分发状态签名公钥。Signer token 至少 32 字节随机值，只用于两个本机账号之间的 HTTP bearer 认证。

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
/etc/mcui-agent/master-ca.pem             Agent 与 Helper 读取，0644 root:root
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

Agent 基础设置继续使用 `/etc/mcui-agent/agent.env` 中的 `MCUI_MASTER_URL`、`MCUI_AGENT_NAME`、`MCUI_AGENT_GROUP`、`MCUI_SERVER_CA` 与 `MCUI_INVITE_FILE`。Helper 的 Master URL 必须是 HTTPS origin，不包含路径、query、用户信息或片段；主机名必须与 Master 证书匹配。

## 4. 为已有节点显式初始化本地账本

新节点在首次注册前会显式创建 Agent 任务账本；Helper 账本始终需要单独的一次性初始化。对已有阶段 1 节点启用阶段 2 前，先确认 Master 任务历史为空，停止 Agent，并用现有 Master/CA/名称参数只运行一次：

```sh
systemctl stop mcui-agent.service
sudo -u mcui-agent /usr/local/bin/mcui-agent \
  -master https://master.example.net:8443 \
  -name edge-01 -group west \
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
  -master-ca /etc/mcui-agent/master-ca.pem \
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
- Agent 账本重启时发现执行中状态会进入 `NEEDS_RECONCILIATION`；Helper 存在未决记录、Master 无法确认前序序号终态或本地账本不匹配时不继续。当前没有在线取消/skip 和账本重建流程；保留原始数据库并按带外人工核对处理。
- 不要删除 SQLite 文件、编辑任务序号、复用请求 ID、删除 Helper ledger 或改写 `NEEDS_RECONCILIATION`。跨数据库快照恢复和独立可信时间仍未实现。

## 7. 当前限制

当前实现只适用于只读状态查询。签名取消/skip、独立外部可信时钟、双库原子恢复、密钥轮换仪式、systemd 启动/沙箱实机演练和 Debian 双架构验收仍未完成。执行本说明中的安装步骤不表示阶段 2 通过或生产部署获批。
