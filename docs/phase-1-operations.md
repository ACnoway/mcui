# 阶段 1 身份通道操作说明

本说明对应阶段 1 的 Master TLS 和空 Agent 身份接口，并提供 Debian 13 的 systemd 单元与 SQLite 备份/恢复候选操作。它不包含 Core 安装、任务执行或生产密钥托管批准；独立安全评审与干净 VM 演练完成前仍不是生产上线批准。

## 信任材料

通过获批的证书与密钥管理流程提供下列文件。不要将私钥、bootstrap token 或邀请文件提交到仓库。

| 文件 | 用途 | 权限要求 |
|---|---|---|
| Master HTTPS 证书 PEM | Master 服务端身份；含服务端证书和所需中间证书 | 公共证书文件 |
| Master HTTPS 私钥 | Master TLS 服务端密钥 | Linux 上仅 Master 账号可读，权限 `0600` |
| Node 客户端 CA 证书 PEM | 验证 Agent 客户端证书 | 公共证书文件 |
| Node 客户端 CA 私钥 | 在线签发注册和轮换 CSR | 仅 Master 账号可读，权限 `0600` |
| Agent 上的 Master CA PEM | Agent 验证 Master HTTPS 服务端 | 通过可信渠道分发的公共 CA 证书 |
| 新 Agent 邀请文件 | 一次性节点注册授权 | 仅专用 Agent 账号可读，权限 `0600` |

Master 服务端证书必须匹配 Agent `-master` 中的 DNS 名，并适用于 TLS serverAuth。Agent 验证证书链和主机名，不支持 TOFU、跳过验证或重定向。在线 Node CA 私钥是高价值密钥，须与 HTTPS 密钥及未来的任务/制品签名密钥分离。离线托管或安全恢复该 CA 的流程尚未获批。

## Debian 13 systemd 部署基线

仓库的 [`mcui-panel.service`](../deploy/systemd/mcui-panel.service) 和 [`mcui-agent.service`](../deploy/systemd/mcui-agent.service) 固定运行用户、可写状态目录和 systemd 沙箱。当前远程检查只验证 unit 语法；它不创建账号、安装文件或启动服务。部署前须在 Debian 13.7 amd64/arm64 干净 VM 逐架构演练并检查沙箱行为。

Master 安装需要 `mcui` 系统用户和组，Agent 节点需要独立 `mcui-agent` 用户和组。以 root:root 安装程序与静态 web 文件，程序不可由服务账号写入：

```sh
useradd --system --home-dir /var/lib/mcui --shell /usr/sbin/nologin mcui
useradd --system --home-dir /var/lib/mcui-agent --shell /usr/sbin/nologin mcui-agent
install -d -o root -g root -m 0755 /opt/mcui/web
install -d -o root -g root -m 0755 /opt/mcui/web/dist
install -o root -g root -m 0755 panel /usr/local/bin/mcui-panel
install -o root -g root -m 0755 agent /usr/local/bin/mcui-agent
install -o root -g root -m 0755 mcuidb /usr/local/bin/mcuidb
cp -a web/dist/. /opt/mcui/web/dist/
chown -R root:root /opt/mcui/web
install -o root -g root -m 0644 deploy/systemd/mcui-panel.service /etc/systemd/system/
install -o root -g root -m 0644 deploy/systemd/mcui-agent.service /etc/systemd/system/
```

把 Master TLS/Node CA 私钥交给 `mcui` 账号所有并设为 `0600`，证书与 web 文件只读。`/etc/mcui/panel.env` 若含 `MCUI_BOOTSTRAP_TOKEN`，必须仅 `mcui` 可读；完成首次 bootstrap 后删除该值并重启服务。Agent 在 `/etc/mcui-agent/agent.env` 读取 `MCUI_MASTER_URL`、`MCUI_AGENT_NAME`、`MCUI_AGENT_GROUP`、`MCUI_SERVER_CA`、`MCUI_INVITE_FILE`；初次注册后清空邀请文件变量、删除邀请文件并重启。不要在 EnvironmentFile 中存放 Agent 私钥。

安装前先检查 unit：

```sh
systemd-analyze verify deploy/systemd/mcui-panel.service deploy/systemd/mcui-agent.service
```

检查通过后，维护人员再执行 systemd reload、enable/start，并确认监听地址、文件权限、服务日志和节点注册结果。Master 默认监听 `0.0.0.0:8443`，须由主机防火墙限制管理访问；当前不支持反向代理终止 TLS。

## 启动 Master

先构建 web 静态文件，再通过受限的服务环境注入一次性 `MCUI_BOOTSTRAP_TOKEN`（不要放在命令行参数或提交到仓库的文件中）。启动参数如下：

```sh
./panel \
  -listen 0.0.0.0:8443 \
  -db /var/lib/mcui/mcui.db \
  -web /opt/mcui/web/dist \
  -tls-cert /etc/mcui/master-chain.pem \
  -tls-key /etc/mcui/master-key.pem \
  -node-ca-cert /etc/mcui/node-ca.pem \
  -node-ca-key /etc/mcui/node-ca-key.pem
```

监听使用 TLS 1.3。TLS 模式要求四个证书/私钥参数全部提供。未启用 TLS 时面板仅允许绑定 loopback，Agent 注册不可用。当前由 Go 服务直接终止 TLS；不支持由反向代理终止 TLS，因为 Cookie Secure 与来源检查依据直连请求连接。

首次启动后，在面板中用一次性 token 初始化首个管理员，设置 12 位以上密码和 Base32 TOTP secret。Bootstrap 账号是全局 `security_admin`。初始化成功后从服务环境移除 bootstrap token。安全管理员可继续在管理员面板创建范围受限的 `auditor`/`operator` 账号；该子集不包含安全管理员委派或全局账号恢复。

安全管理员可在界面创建 `auditor`/`operator` 范围账号；服务端拒绝超出发起者权限的节点 ID 或节点组，并且只返回新账号的一次性 TOTP seed。新账号初始密码由安全管理员输入并通过独立可信渠道交付；密码和 TOTP seed 不会出现在账号列表或审计记录。禁用账号需 CSRF 和 MFA 复验，并会撤销其全部服务端会话；不能通过此接口创建/禁用 `security_admin` 或禁用自己。丢失全局安全管理员凭据时需使用经过批准的带外恢复程序，当前项目尚未实现该流程。

## 注册 Agent

1. 通过 HTTPS 登录面板。为目标节点组创建邀请，并尽量使用短有效期（API 接受 60 秒至 24 小时）。邀请 token 只展示一次，需经可信渠道转交。
2. 将 token 放入只有专用 Agent 账号可读取的文件。不要放入进程参数、shell history、支持包或日志。
3. 使用 Master DNS 名和预置信任 CA 启动不含 Core 的 Agent：

   ```sh
   ./agent \
     -master https://master.example.net:8443 \
     -server-ca /etc/mcui/master-ca.pem \
     -name edge-01 \
     -group west \
     -invite-file /run/mcui-agent/invite
   ```

4. Agent 本地生成 Ed25519 私钥和 CSR。Linux 下身份保存路径为 `/var/lib/mcui-agent/identity.json`，目录权限为 `0700`、文件权限为 `0600`；`MCUI_AGENT_STATE` 可设置另一个状态文件路径。Agent 二进制在非 Windows 系统会拒绝以 root 运行，应使用专用非 root 账号。仓库提供最小权限 systemd unit 和部署手册；仍需在干净 Debian VM 验证服务账号、文件权限和沙箱行为。
5. 注册完成后删除邀请文件。注册重试具幂等性；邀请只能使用一次且会过期。

## 轮换、禁用与恢复

- 当前证书剩余期限不超过 7 天时，Agent 会生成并先保存一把新本地密钥，再请求轮换。Master 允许旧证书最多重叠 24 小时；禁用节点会立即撤销所有已登记证书。每次 Agent 请求都会检查节点和证书状态。
- 创建邀请或禁用节点需要安全管理员权限及最近 10 分钟内的 MFA。离线 Agent 在重新连接前无法获知远端撤销。
- Agent 密钥或身份文件丢失时，先停止 Agent 并禁用旧节点。核实本地节点控制权后签发新的短时邀请，为 Agent 准备新的状态目录并以新节点身份注册。当前接口不支持安全的同 ID 恢复，也没有数据库恢复流程；不要复用旧邀请或直接修改 SQLite。
- Node CA 私钥、Master 信任根或数据库丢失/疑似失陷时，停止注册与证书轮换。所需的独立恢复仪式和一致性核对尚未实现；只能通过获批的带外流程恢复。

## SQLite 备份与恢复候选

`mcuidb` 对在线 SQLite 数据库执行 `VACUUM INTO` 一致性快照，输出新文件、设为仅所有者可读写并运行 `PRAGMA integrity_check`。恢复命令只生成新路径的候选文件，不覆盖当前数据库：

```sh
install -d -o mcui -g mcui -m 0700 /var/lib/mcui/backups
sudo -u mcui /usr/local/bin/mcuidb backup -db /var/lib/mcui/mcui.db -out /var/lib/mcui/backups/snapshot.db
/usr/local/bin/mcuidb verify -db /var/lib/mcui/backups/snapshot.db
/usr/local/bin/mcuidb restore -backup /var/lib/mcui/backups/snapshot.db -out /var/lib/mcui/restore-candidate.db
/usr/local/bin/mcuidb verify -db /var/lib/mcui/restore-candidate.db
```

数据库、节点撤销状态、管理员凭据和审计均属敏感数据。备份必须放在受访问控制和静态加密保护的存储上，并有独立权限与保留计划；`mcuidb` 不加密备份，也不提供防篡改/新鲜度证明。恢复旧数据可能复活当时尚未记录的撤销、邀请或管理员变更。必须先停服并用独立可信检查点核对新鲜度；无法证明状态连续时，不得把候选文件放到线上路径或恢复节点注册/轮换。候选文件的完整性通过不等于恢复获准。

## 当前限制

仓库提供加固 systemd unit、`mcuidb` 备份/校验/恢复候选命令和部署说明；本轮远端静态/语法检查不等于干净机器安装或生产恢复演练。密钥生成与托管仪式、证书撤销列表导出、加密备份和独立新鲜度检查点、管理员恢复，以及双架构干净 VM 演练仍未完成。阶段 1 没有远程任务、Helper 或 Core 操作。
