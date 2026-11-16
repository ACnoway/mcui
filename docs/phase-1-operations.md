# 阶段 1 身份通道操作说明

本说明对应当前 Master TLS 和 Agent 身份接口。尚未定义正式密钥仪式、systemd 单元或数据库备份/恢复步骤；相关门槛完成评审和演练前，不应将其视为生产部署手册。

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

首次启动后，在面板中用一次性 token 初始化首个管理员，设置 12 位以上密码和 Base32 TOTP secret。Bootstrap 账号是全局 `security_admin`。初始化成功后从服务环境移除 bootstrap token。当前界面不能创建其他管理员或分配受限范围，不应将首管理员流程当作完整的多管理员运维模型。

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

4. Agent 本地生成 Ed25519 私钥和 CSR。Linux 下身份保存路径为 `/var/lib/mcui-agent/identity.json`，目录权限为 `0700`、文件权限为 `0600`；`MCUI_AGENT_STATE` 可设置另一个状态文件路径。Agent 二进制在非 Windows 系统会拒绝以 root 运行，应使用专用非 root 账号。仓库暂未提供服务账号、systemd unit、安装包或文件系统加固配置。
5. 注册完成后删除邀请文件。注册重试具幂等性；邀请只能使用一次且会过期。

## 轮换、禁用与恢复

- 当前证书剩余期限不超过 7 天时，Agent 会生成并先保存一把新本地密钥，再请求轮换。Master 允许旧证书最多重叠 24 小时；禁用节点会立即撤销所有已登记证书。每次 Agent 请求都会检查节点和证书状态。
- 创建邀请或禁用节点需要安全管理员权限及最近 10 分钟内的 MFA。离线 Agent 在重新连接前无法获知远端撤销。
- Agent 密钥或身份文件丢失时，先停止 Agent 并禁用旧节点。核实本地节点控制权后签发新的短时邀请，为 Agent 准备新的状态目录并以新节点身份注册。当前接口不支持安全的同 ID 恢复，也没有数据库恢复流程；不要复用旧邀请或直接修改 SQLite。
- Node CA 私钥、Master 信任根或数据库丢失/疑似失陷时，停止注册与证书轮换。所需的独立恢复仪式和一致性核对尚未实现；只能通过获批的带外流程恢复。

## 当前限制

仓库未提供加固 service unit、密钥生成/托管仪式、证书撤销列表导出、数据库备份命令、恢复工作流或干净机器安装测试。生产使用前需完成并记录这些事项。阶段 1 没有远程任务、Helper 或 Core 操作。
