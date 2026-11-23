# Xray 受控入站

面板管理模式允许单管理员给节点预先批准的端口分配用户。使用该模式时，先完成本页的节点准备第 1–3 步，再建立节点目录和面板草稿。节点、Master、Agent、Helper 和独立签发服务须使用支持该模式的版本。

## VLESS、VMess 和 Shadowsocks 2022

这些模板适用于 Linux amd64 的 Xray `v26.10.31`，沿用独立签名清单、节点预配端口及用户授权。监听地址固定为专用命名空间的 `127.0.0.1`，业务路由只允许节点批准的字面 IPv4 和 TCP 端口。启用前更新 Master、独立签发服务、Agent 和 Helper。

| 协议 | 使用方式 |
|---|---|
| VLESS | 用户使用小写 UUIDv4，模板使用本地 RAW TCP，VLESS `decryption` 为 `none`。 |
| VMess | 用户使用独立的小写 UUIDv4，客户端使用 `aes-128-gcm`，服务端与客户端需要正确时间。 |
| Shadowsocks 2022 | 固定 `2022-blake3-aes-256-gcm`，服务端和各用户分别使用 32 字节随机值的有填充 Base64 密钥。向用户交付 `服务端密钥:该用户密钥`。 |

在 `managed-inbounds.json` 中用 `port_protocols` 为 `ports` 中的端口指定模板，并在 `protocol_credentials` 中登记各协议可授权的用户。以下展示新增字段，可与下节的 `credentials` 配合使用。

```json
{
  "ports": [1081, 1082, 1083],
  "port_protocols": { "1081": "vless", "1082": "vmess", "1083": "shadowsocks" },
  "protocol_credentials": {
    "vless": { "alice": "<Alice 的 VLESS UUID>" },
    "vmess": { "alice": "<Alice 的另一个 VMess UUID>" },
    "shadowsocks": { "alice": "<Alice 的 Shadowsocks 用户密钥>" }
  },
  "shadowsocks_server_key": "<节点的 Shadowsocks 服务端密钥>"
}
```

可在 Linux 用 `cat /proc/sys/kernel/random/uuid` 生成 UUIDv4，用 `openssl rand -base64 32` 生成每个 Shadowsocks 密钥。为每人、每种协议独立生成凭据。轮换后保存节点文件，等待心跳报告新候选摘要，再从面板签发新修订。用户凭据通过部署方的安全渠道交付。浏览器使用选中端口对应的凭据生成原生 Xray 配置。

### 三种协议的隔离验收

2026-11-23 在 `ro` 上从 `/root/mcui` 建立隔离检出，验证提交 `e8bc5d5c3e335098489946404d0065e09c88098c`。数据面使用 Debian 13.7 amd64、内核 `6.12.107+deb13-cloud-amd64`，服务端与客户端在无默认路由的独立网络命名空间中运行。Xray 官方 `v26.10.31` amd64 ZIP 的 SHA-256 已核对。

| 检查 | 结果 |
|---|---|
| 配置和订阅 | 面板集成测试覆盖按协议限制用户、签名绑定、旧 Agent 拒领新模板任务及订阅端口隔离。既有订阅格式继续兼容。 |
| 真实连接 | 使用节点模板生成服务端配置，用订阅页共用代码生成 VLESS、VMess 和 Shadowsocks 2022 客户端配置。每种客户端均通过 Xray 预检并读取授权测试目标。为同一协议登记但未获该端口授权的测试账号被拒绝。客户机能直连的未批准目标 TCP 端口也无法经代理访问。 |
| 授权撤销与轮换 | 重启服务端应用修订后，撤销的 VLESS 客户端无法连接，保留的 VMess 授权继续可用。Shadowsocks 2022 拒绝旧用户密钥并接受新密钥。 |
| 静态检查与构建 | 本地通过相关 Go 测试、Linux `go vet`、双架构编译、协议向量和前端构建。`ro` 使用 Go `1.27.4`、Node.js `26.13.1`、pnpm `12.17.0` 通过 `scripts/check-static.sh`，完成 Master 与 Agent 的 amd64/arm64 安装包构建及 SHA-256 校验。运行验收使用 amd64。 |

此轮数据面使用真实 Xray 进程，签发、投递和恢复边界由代码集成测试覆盖。Xray 用量显示 `UNSUPPORTED`，精确额度禁用。

## Trojan 与 TLS 1.3

Trojan 模板适用于 Linux amd64 的 Xray `v26.10.31`。监听固定在专用命名空间的 `127.0.0.1`，使用 RAW TCP 和 TLS 1.3，业务流量只允许到达节点批准的 IPv4 TCP 目的端点。启用前更新 Master、独立签发服务、Agent 和 Helper。[Xray Trojan 配置](https://xtls.github.io/en/config/inbounds/trojan.html) · [Xray TLS 配置](https://xtls.github.io/en/config/transports/tls.html)

1. 节点 root 在私有目录生成用于 `localhost` 的自签名 Ed25519 服务器证书和 PKCS#8 私钥。为每位用户生成独立的 32 字节随机密码，按无填充 Base64URL 编码。

   ```sh
   umask 077
   openssl req -x509 -newkey ed25519 -noenc -days 90 -subj '/CN=localhost' \
     -addext 'subjectAltName=DNS:localhost' \
     -addext 'basicConstraints=critical,CA:FALSE' \
     -addext 'keyUsage=critical,digitalSignature' \
     -addext 'extendedKeyUsage=serverAuth' \
     -keyout trojan.key -out trojan.crt
   ```

2. 在节点的 `managed-inbounds.json` 中配置下列字段，并保留同一文件中的制品摘要与批准目的端点。`certificate` 和 `private_key` 分别使用生成文件的完整 PEM 文本，按 JSON 字符串保存。文件归节点 root 所有，权限设为 `0600`。同一节点的受控 Trojan 端口共用这套服务器证书。

   ```json
   {
     "ports": [1084],
     "port_protocols": { "1084": "trojan" },
     "protocol_credentials": { "trojan": { "alice": "<Alice 的 Trojan 密码>" } },
     "trojan_tls": { "certificate": "<证书 PEM>", "private_key": "<私钥 PEM>" }
   }
   ```

3. 在面板核对端口的 TLS 证书 SHA-256，勾选用户，保存草稿并签发。Helper 校验证书与私钥匹配、证书有效期及签名草稿中的摘要。下载的配置使用 Xray 的原生 Go TLS 握手（`fingerprint: "unsafe"`），独立信任该公开证书并校验 `localhost` 和有效期。密码由节点管理员交付。
4. 轮换证书时原子更新节点目录中的证书和私钥，等待新心跳，核对新摘要并重新保存草稿，再签发新修订。新修订生效后重新签发订阅，让客户端下载带新证书的配置。旧证书的客户端连接会被拒绝。

### Trojan TLS 隔离验收

2026-11-23 在 `ro` 从 `/root/mcui` 建立隔离检出，验证提交 `ae4c15927b22d9fd3baf7b3d695739e85a8655e1`。真实服务端和客户端运行在无默认路由的 Debian 13.7 amd64 网络命名空间，内核 `6.12.107+deb13-cloud-amd64`，使用已复核 SHA-256 的官方 Xray `v26.10.31`。

| 检查 | 结果 |
|---|---|
| 签名与订阅 | 集成测试核对证书摘要、草稿和已签名任务一致。早期 Agent 不领取 Trojan TLS 草稿，订阅只向有相应端口授权的用户返回公开证书。未签发的证书变更无法通过订阅下放。 |
| TLS 握手 | OpenSSL 核对 TLS 1.3、`localhost` 和批准证书，TLS 1.2 与错误 SNI 均被拒绝。用订阅生成器输出的原生 Xray 客户端可通过正确证书连接，换用另一张 `localhost` 证书即失败。 |
| 节点策略 | 客户端成功读取批准目标。有效密码所属的用户若没有该端口授权，无法请求目标。另一个已启动且可在命名空间内直连的目标端口也被代理拒绝。 |
| 证书轮换 | 旧草稿无法渲染新证书。重启应用带新证书摘要的配置后，信任旧证书的客户端连接失败，信任新证书的客户端恢复连接。 |
| 静态检查与构建 | 本地相关 Go 测试、Linux `go vet`、双架构编译、协议向量和前端构建通过。`ro` 以 Go `1.27.4`、Node.js `26.13.1`、pnpm `12.17.0` 通过 `scripts/check-static.sh`，完成 Master、Agent 双架构安装包与 SHA-256 校验。运行验收使用 amd64。 |

## VLESS 与 REALITY

模板适用于 Linux amd64 的 Xray `v26.10.31`，使用回环 RAW TCP 和 REALITY。Xray 会把未通过 REALITY 握手验证的连接交给握手目标。因此模板把目标固定为同一专用命名空间内的 `127.0.0.1:10443`，使用固定服务器名 `localhost`。节点 root 在启用前为这个地址准备专用 TLS 1.3 应答服务，提供覆盖 `localhost` 的证书和静态响应。`10443` 保留给应答服务。业务连接仍须通过 VLESS 用户授权和原有的固定 IPv4 TCP 目的策略。[Xray REALITY 配置](https://xtls.github.io/en/config/transports/reality.html#realityobject)

1. 更新 Master、独立签发服务、Agent 和 Helper。节点 root 用已校验的 `xray x25519` 生成节点密钥，用 `cat /proc/sys/kernel/random/uuid` 和 `openssl rand -hex 8` 为每个账号分别生成 UUIDv4 和 Short ID。
2. 在节点 `managed-inbounds.json` 加入如下字段，并保留制品摘要和批准的业务目的。`reality_private_key` 为节点 X25519 私钥，用户名下的凭据采用 `UUID:ShortID`。普通 VLESS 与 REALITY 使用分别登记的 UUID。Short ID 为 16 位小写十六进制。

   ```json
   {
     "ports": [1085],
     "port_protocols": { "1085": "vless-reality" },
     "protocol_credentials": { "vless-reality": { "alice": "<UUIDv4>:<Short ID>" } },
     "reality_private_key": "<节点 X25519 私钥>"
   }
   ```

3. 在面板核对回环端口及 REALITY 公钥，保存授权草稿并签发。订阅携带已应用修订的公钥。用户在订阅页输入节点管理员交付的 `UUID:ShortID`，下载原生 Xray 配置。同步客户端和节点的时钟，模板允许 120 秒握手时钟偏差。
4. 轮换节点密钥后核对公钥并重新保存草稿，再签发新修订并重发订阅。撤销账号时移除该用户的端口授权并应用新修订。该用户的 UUID 和对应 Short ID 都会从该端口的生效配置中移除。

### VLESS REALITY 隔离验收

2026-11-23 在 `ro` 从 `/root/mcui` 建立隔离检出，验证提交 `001b8d8eb172092474d15bb55f92a77e9b27d765`。真实服务端与客户端使用无默认路由的 Debian 13.7 amd64 网络命名空间，内核 `6.12.107+deb13-cloud-amd64`，官方 Xray `v26.10.31` 制品已核对 SHA-256。回环 TLS 应答端启用 TLS 1.3、X25519 和 ALPN `h2`、`http/1.1`，使用 `localhost` 测试证书。

| 检查 | 结果 |
|---|---|
| 签名与订阅 | 集成测试覆盖公钥与端口授权绑定、旧 Agent 拒领 REALITY 任务、公开订阅只返回用户所获授权的公钥。配置和已应用清单均从节点侧重新核对。 |
| 真实连接 | 订阅生成的 Xray 客户端使用批准的 UUID 和 Short ID 获取测试响应。错误公钥、错误 UUID 和未授权账号均被拒绝。可在命名空间内直接访问的未批准目标端口无法经代理访问。 |
| 回环握手目标 | 普通 HTTPS 请求从 REALITY 端口获得 `127.0.0.1:10443` 的静态测试响应，验证握手回落留在指定的命名空间。 |
| 密钥轮换与撤销 | 更换节点密钥后，绑定旧公钥的草稿被拒绝。新配置运行后，旧公钥客户端无法连接，新公钥客户端可用。重新应用授权后，撤销账号无法连接，获准的另一账号可以连接。 |
| 静态检查与构建 | 本地相关 Go 测试、Linux `go vet`、双架构编译、协议向量和前端构建通过。`ro` 以 Go `1.27.4`、Node.js `26.13.1`、pnpm `12.17.0` 通过 `scripts/check-static.sh`，完成 Master、Agent 双架构安装包及 SHA-256 校验。运行验收使用 amd64。 |

## 受控公网 TCP 接入

节点 root 可为 Trojan/TLS 或 VLESS/REALITY 端口配置一个已绑定于节点宿主机的公网 IPv4 和一个 TCP 端口。systemd 在宿主网络接受连接，将连接交给专用命名空间中的 `systemd-socket-proxyd`。中继固定连向 `127.0.0.2:<节点端口>`，由 Xray 做协议认证及业务目的校验。普通回环入站仍使用 `127.0.0.1`。[systemd-socket-proxyd](https://www.freedesktop.org/software/systemd/man/latest/systemd-socket-proxyd.html)

1. 确认本机具有所选公网 IPv4，更新 Master、独立签发服务、Agent 和 Helper。将仓库中的 [`mcui-xray-publish@.service`](../deploy/systemd/mcui-xray-publish@.service) 安装到 `/etc/systemd/system/`。在当前 Xray 服务 drop-in 的 `IPAddressAllow` 中追加 `127.0.0.2/32`，保留原回环、已批准业务目的和 `IPAddressDeny=any`。
2. 为当前节点内端口准备对应的 `.socket`。例如节点内端口为 `1084` 时，创建 `/etc/systemd/system/mcui-xray-publish@1084.socket`，用节点实际公网地址替换 `PUBLIC_IPV4`。编辑完执行 `systemctl daemon-reload`。

   ```ini
   [Socket]
   ListenStream=PUBLIC_IPV4:443
   Accept=no
   Service=mcui-xray-publish@1084.service

   [Install]
   WantedBy=sockets.target
   ```

3. 在节点 `managed-inbounds.json` 的现有加密端口配置中加入 `"public_endpoints": {"1084": {"address": "PUBLIC_IPV4", "port": 443}}`。等待节点心跳，核对面板地址、服务端身份及用户，保存草稿并签发。Helper 复验公网套接字的地址、端口、启动单元和中继的命名空间与回环限制。
4. 配置任务成功后，由节点 root 执行 `systemctl enable --now mcui-xray-publish@1084.socket`。签发订阅，使用可达该 IPv4 的客户端连接，核对凭据拒绝及批准目标。停止公网入口时停用 `.socket` 并停止其 `.service`。更换宿主地址或端口前先关闭旧入口，更新单元与节点目录，再重新保存草稿、签发及激活。

公网入口为 TCP 字节中继，Xray 看到的对端是命名空间内的中继地址。移除授权或将该端口恢复为回环模板后，原公网套接字无法到达该端口的本地服务。外部来访地址过滤可在宿主机防火墙配置。

## 面板管理入站与授权

1. 在节点 root 的 `/etc/mcui-xray` 目录下创建 `managed-inbounds.json`，目录和文件分别为 `root:root`、`0700` 和 `0600`。发布摘要、目的 IPv4 和 TCP 端口须匹配已审核制品和节点网络策略。每个用户分别生成 32 字节随机密码，再按无填充 Base64URL 编码。

   ```json
   {
     "release_sha256": "<已安装发布制品 SHA-256>",
     "ports": [1080, 1081],
     "http_ports": [1081],
     "credentials": {
       "alice": "<Alice 的随机密码>",
       "bob": "<Bob 的随机密码>"
     },
     "destination_ip": "<批准的公网 IPv4>",
     "destination_port": 443
   }
   ```

2. `http_ports` 可省略。它只能列出 `ports` 中的唯一端口，指定这些端口仅使用 HTTP 代理和 Basic 认证，关闭透明代理。其余端口使用原 Xray SOCKS 模板，锁定版也允许使用同一组账号的 HTTP 代理请求。两种模板仅在专用网络命名空间的 `127.0.0.1` 监听，只允许节点批准的单一字面 IPv4 和 TCP 端口。[锁定版 SOCKS 实现](https://github.com/XTLS/Xray-core/blob/v26.10.31/proxy/socks/server.go#L32-L84) · [Xray HTTP 配置](https://xtls.github.io/config/inbounds/http.html)
3. 在节点详情的「入站授权草稿」中勾选各端口允许的用户名并保存。未授予用户的端口不监听。最多启用 4 个端口、登记 8 个用户名并同时分配 16 条端口授权。用户名以小写字母开头，最多 24 个字符，可含小写字母、数字、连字符和下划线。
4. 等待节点心跳并刷新。核对已应用授权、端口类型、草稿和节点报告的 SHA-256，通过「下发受控入站」确认并完成 MFA 复验。签发后草稿可以继续编辑，已签发任务仍按当时批准的授权执行。以成功任务及节点上报的已应用修订确认变更生效。
5. 撤销授权时取消对应选项并重新下发。保存并应用空草稿会移除全部监听。轮换密码时由节点 root 原子更新目录文件，通知客户端，再用相同授权重新预览并下发新摘要。修改 `http_ports` 后等待心跳并重新保存草稿。仅编辑草稿或节点文件不会中断当前连接。应用配置会重启运行中的 Xray，撤销从成功应用的新修订开始生效。

节点目录存在时启用面板管理模式。移除该文件后可由原单用户模式准备并签发新的配置，当前已提交配置仍可运行。目录读错、端口类型或摘要不匹配时停止下发该候选，保留上一次提交的配置。面板、任务和审计只包含用户名、端口、类型、状态和摘要。密码由节点 root 保管，通过部署方的安全渠道交给授权客户端。启用 `http_ports` 前，先更新 Master、Agent、Helper 和独立签发服务。

## 节点本地单用户模板

首个模板适用于 Linux amd64 的 Xray `v26.10.31`，仍需匹配独立签名稳定清单中的精确制品。节点本地 root 审批监听端口、密码和单一 IPv4 TCP 目标。面板管理员只审批候选端口和配置指纹。模板固定用户 `mcui`、回环监听、密码认证及默认拒绝路由。[配置策略](./config-policy.md) · [Xray SOCKS 文档](https://xtls.github.io/config/inbounds/socks.html)

## 节点准备

1. 按[阶段 3 操作手册](./phase-3-operations.md)部署使用同版程序的 Master、签发端、Agent、Helper、`mcui-xray` 和 Xray units。安装清单批准的 `v26.10.31`。更新已有节点 unit 后运行 `systemctl daemon-reload` 和 `mcui-xray recover`。
2. 节点 root 创建专用命名空间 `/run/netns/mcui-xray`，启用该命名空间的回环接口，并按部署拓扑配置通向所批准目标的受限路由与防火墙。测试可用 `ip netns add mcui-xray` 和 `ip -n mcui-xray link set lo up` 创建命名空间。持续部署应由本地 systemd 依赖在 Xray 恢复前重新建立该命名空间和网络规则。
3. 在节点的 `/etc/systemd/system/mcui-xray.service.d/` 添加本地 drop-in，用精确地址替换示例占位符并执行 `systemctl daemon-reload`。保留默认 `IPAddressDeny=any`、`PrivateNetwork=yes`、动态用户和固定标准输入设置。预检 unit 保持默认独立网络和无允许地址。迁移目标时，在新修订提交前保留上一个已提交目标的网络许可，以便启动回滚。

```ini
[Service]
NetworkNamespacePath=/run/netns/mcui-xray
IPAddressAllow=127.0.0.1/32
IPAddressAllow=<批准的目标 IPv4>/32
```

4. 确认 `/etc/mcui-xray` 为 `root:root`、`0700` 的真实目录。在其中以 `root:root`、`0600` 创建 `controlled-inbound.json`。将示例字段替换为精确已安装制品摘要、1024..65535 的监听端口、32 字节随机值的无填充 Base64URL 密码、批准的 IPv4 及 TCP 端口。可用 `openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'` 生成测试密码。密码仅保存在节点和授权客户端。

```json
{
  "release_sha256": "<已安装发布制品 SHA-256>",
  "listen_port": 1080,
  "password": "<无填充 Base64URL 随机密码>",
  "destination_ip": "<批准的公网 IPv4>",
  "destination_port": 443
}
```

## 下发、验证与恢复

1. 等待节点心跳刷新。在节点的「Xray 远程管理」选择「下发受控入站」，核对候选端口和 SHA-256，完成确认及当前 MFA。选项需要有效签名清单包含当前制品，并且节点汇报的候选内容有变化。
2. 在面板刷新任务结果和已应用修订。运行中的节点切换时会重启 Xray。原先已停止的节点会短暂启动候选作健康检查，然后恢复停止状态。
3. 让测试客户端在同一专用命名空间中访问 `127.0.0.1:<监听端口>`，用用户 `mcui` 和本地密码请求批准的字面 IPv4 与端口。分别验证错误密码、目标端口不匹配和域名请求被拒绝。客户端测试凭据使用受限权限的本地配置文件传入。
4. 配置预检、策略摘要或授权校验失败时，任务返回 `FAILED`。候选启动失败且成功恢复时返回 `ROLLED_BACK`。未决事务用原签名任务对账，必要时由节点 root 执行 `mcui-xray recover`。移除候选策略文件会阻止新的下发。停用运行中的入站可在面板停止 Xray。跨版本切换成功后使用新版本的引导配置。

面板显示候选和已应用配置的摘要、端口及修订号。节点配置和密码保存在节点的私有目录。[阶段路线图](./phased-development-workflow.md#阶段-4xray-完整业务闭环与最小演示)

## 客户端订阅

1. 先应用面板管理模式的授权草稿，等待配置任务成功和节点上报相同的修订。节点详情「客户端订阅」会列出当前可签发的账号。
2. 签发链接并按提示完成 MFA。链接只显示一次，30 天后过期。同一节点和用户只保留一个令牌。再次签发会轮换令牌并使旧链接立即失效。
3. 用户在浏览器打开 HTTPS 链接，选择有权访问的节点回环端口，输入节点管理员交付的密码，下载 `xray-client.json`。浏览器在本地生成配置，按端口选择 SOCKS 或 HTTP 出站。文件包含凭据，应以仅当前用户可读的权限保存。
4. 在可访问节点 `127.0.0.1` 的环境，用 `xray run -config xray-client.json` 启动客户端。隔离验收在同一网络命名空间内运行服务端和客户端。客户端 SOCKS5 也只监听回环，并要求相同用户和密码。

订阅绑定已提交的配置修订和摘要。节点离线、Xray 停止或有未决生命周期任务时暂停拉取。应用新修订、节点重新接入、轮换及撤销会使旧链接失效。撤销链接影响后续下载。撤销已下载配置的连接权限须应用移除用户授权或轮换密码的新修订。

浏览器把 URL 片段中的令牌作为 HTTPS `Authorization: Bearer` 请求 `GET /api/v1/subscription`。该端点按来源地址限流并禁用响应缓存，返回当前修订许可的端口及用户名。只有原 SOCKS 端口时继续返回 `schema_version: 1`。仅增加 HTTP 专用类型时返回 `schema_version: 2` 和 `http_ports`。含 VLESS、VMess、Shadowsocks 2022、Trojan 或 REALITY 时用 `port_protocols` 标明类型，默认返回 `schema_version: 3`。用户获准的端口中含公网接入时返回 `schema_version: 4`，以 `public_endpoints` 将节点内端口映射到签名批准的公网地址和 TCP 端口。Trojan 订阅返回 `trojan_trust`，VLESS/REALITY 订阅返回 `reality_public_key`。Master 只保存订阅令牌的 SHA-256 摘要、修订及到期时间，审计记录操作和目标用户。部署方的反向代理须避免记录 `Authorization` 请求头和签发响应正文。恢复旧备份时，使用独立检查点核对撤销状态，或由管理员复核并撤销恢复的链接后再开放订阅端点。

### 订阅验收记录（2026-11-23）

在 `ro` 从 `/root/mcui` 建立 Debian 13 amd64 隔离检出，验证提交 `579c84f`。集成测试覆盖管理员节点范围、CSRF、MFA、摘要落盘、审计脱敏、拉取端口隔离、到期、轮换、撤销、限流，以及已签名任务与节点快照不一致时暂停拉取。

在无默认路由的隔离网络中，用浏览器页面共用的生成器输出客户端配置，核对上游 ZIP 摘要后使用真实 Xray `v26.10.31` 运行服务端和客户端。两名授权用户均通过自己的原生客户端访问测试目标，缺少或输错本地密码时被拒绝。重启服务端应用移除授权的配置后，旧客户端连接失败，其余用户仍可连接。

同一提交通过 `scripts/check-static.sh`，主控、存储、任务投递和 Xray 配置的竞态测试，以及 Master amd64/arm64 安装包构建和 SHA-256 校验。

## 用户级统计与额度

面板为已安装的 Xray 显示用户流量 `UNSUPPORTED` 和精确额度禁用。受控 SOCKS5 配置沿用现有节点隔离，统计服务只在独立验证环境临时启用。

锁定版 Xray 将 SOCKS5 认证用户名写入用户计数的标识。默认 `splice` 快速转发路径在该次拷贝返回后才累加下行字节，长连接中的定时读数可能落后于已收到的流量。Go 进程重启后，原有内存计数也无法用于找回漏采的字节。 [Xray 用户映射](https://github.com/XTLS/Xray-core/blob/v26.10.31/proxy/socks/protocol.go#L133-L154) · [Xray 转发计数](https://github.com/XTLS/Xray-core/blob/v26.10.31/proxy/proxy.go#L723-L750)

在测试机准备官方 `v26.10.31` 的 `Xray-linux-64.zip`，从仓库根目录运行以下命令。探针核对 ZIP 摘要，为测试目标配置隔离命名空间的回环地址，通过 `0600` Unix socket 多次读取用户计数，并对比默认和禁用 `splice` 模式在连接中、关闭后与进程重启时的结果。

```bash
sudo unshare --net -- bash -eu -c '
  ip link set lo up
  ip addr add 93.184.216.34/32 dev lo
  exec python3 scripts/verify-xray-user-stats.py "$1"
' bash /path/to/Xray-linux-64.zip
```

### 计数实测

2026-11-23 在 `ro` 的 Debian 13 amd64 隔离检出运行探针，提交 `d27acf6`，内核 `6.12.107+deb13-cloud-amd64`，Python `3.13.5`。使用上文同一份经 SHA-256 校验的官方 Xray 制品。每个用户向独立测试端点发送 262,147 字节，实际收到 1,048,583 字节。以下数字是节点进程内的 TCP 用户计数。

| 场景 | 上行字节 | 下行字节 |
|---|---:|---:|
| 默认 `splice`，已传完但连接仍开着 | 262,147 | 0 |
| 默认 `splice`，关闭连接后 | 262,147 | 1,048,583 |
| 禁用 `splice`，已传完但连接仍开着 | 262,147 | 1,048,583 |
| 禁用 `splice`，关闭连接后 | 262,147 | 1,048,583 |

两种模式下均验证了 Alice 与 Bob 的计数互不影响、拒绝认证不计量，以及重复查询不重置计数。重启后查询为空。禁用 `splice` 的结果仅证明这组样本的连接内读数，持久化上报和缺口恢复仍待验证。面板保持 `UNSUPPORTED`，未知用量留空。

同一提交通过 `scripts/check-static.sh`、面板 Xray 竞态回归，以及 Master amd64/arm64 安装包构建和 SHA-256 校验。

## 隔离验收记录

2026-11-21 在 `ro` 从 `/root/mcui` 建立临时检出验证提交 `1972662`。数据面使用无外网网卡的 Debian 13 amd64 QEMU 客户机，内核 `6.12.107+deb13-cloud-amd64`，systemd `257.13-1~deb13u1`。官方 Xray `v26.10.31` amd64 ZIP 的 SHA-256 为 `e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214`。[官方发布页](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31)

| 检查 | 结果 |
|---|---|
| 面板签发与投递 | 集成测试核对配置指纹、发布清单、双签名、确认与 MFA。候选发生变化和旧 Agent 领取均被拒绝，支持配置的 Agent 可领取并回报。 |
| 真实 Xray 数据面 | 使用系统自带 systemd 运行 Xray 和隔离预检。curl 通过认证 SOCKS5 获得授权 IPv4 TCP 测试端点的预期 HTTP 内容。错误密码、未授权端口、域名和回环地址作为目的均被拒绝。 |
| 启停与恢复 | 占用候选监听端口触发启动失败。旧配置、正在运行状态及原密码恢复，原客户端再次连通。对账返回保存的 `ROLLED_BACK`。停止后连接失败，启动后恢复。 |
| 构建与回归 | `scripts/check-static.sh`、相关 Go 包的竞态检查、`scripts/build-runtime-release.sh` 和两个发布 ZIP 的 SHA-256 核验均通过。arm64 完成构建和包摘要核验。 |

### 面板入站授权验证（2026-11-23）

在 `ro` 从 `/root/mcui` 建立隔离检出，验证提交 `b17281b`。环境为 Debian 13 amd64、内核 `6.12.107+deb13-cloud-amd64`、systemd `257.13-1~deb13u1`。使用 Go `1.27.4`、Node.js `26.13.1`、pnpm `12.17.0`。实际连接使用上述官方 Xray `v26.10.31` amd64 制品并重新核对 ZIP 的 SHA-256。

| 检查 | 结果 |
|---|---|
| 草稿与任务 | `scripts/check-static.sh` 通过。集成测试覆盖节点范围、CSRF、草稿版本冲突、重复保存、未预览拒绝、独立签发及旧 Agent 隔离。原单用户签发和双签名跨实现向量通过。 |
| 真实连接与撤销 | 在无默认路由的隔离网络命名空间，以生成的配置启动真实 Xray。两个用户可分别通过有授权的端口取得 TCP 测试端点的 HTTP 内容。错误密码、未授权端口组合和未批准目标端口被拒绝。重新加载撤销配置后，原用户无法连接，其余用户仍可连接。空草稿通过 Xray 预检并关闭全部监听。 |
| 运行时事务 | Go 运行时测试覆盖凭据变化时拒用旧摘要、空草稿提交及旧配置启动失败回滚。真实连接验证使用独立 Xray 进程，systemd 故障回滚实机证据沿用上面的单用户验收。 |
| 竞态与发布包 | `go test -race -count=1` 通过 Agent、任务执行、Helper、签发、主控、协议、投递、Xray 配置和运行时包。Runtime 的 amd64/arm64 ZIP、Master 双架构安装包及其 SHA-256 校验均通过。arm64 完成构建和制品校验。 |

### 空 Agent 最小演示（2026-11-23）

通过 SSH 在 `ro` 从 `/root/mcui` 建立隔离检出，验证提交 `c88777c8235e5a70bd91703587dd692f0314778c`。在无外网网卡的 Debian 13.7 amd64 KVM/QEMU 客户机运行，内核 `6.12.107+deb13-cloud-amd64`，systemd `257.13-1~deb13u1`。chrony `4.9` 使用隔离 NTS 服务和测试 CA。独立签发进程与 Helper 使用本机只读时间监控接口。演示使用独立测试签名密钥、私有 HTTPS 制品镜像和上述官方 Xray `v26.10.31` amd64 ZIP，并核对官方 ZIP 的 SHA-256。管理操作通过面板的 HTTPS API 自动化执行。

| 检查 | 结果 |
|---|---|
| 注册与安装 | 在尚未安装 Agent 和 Xray 的客户机执行面板生成的安装命令，验证 Agent、Helper 启动以及节点认证心跳。配置节点本地信任后，签名任务 `#1 core.install` 返回 `SUCCEEDED`。面板上报制品版本和摘要，systemd 确认 Xray 正在运行。 |
| 入站与统计 | 节点 root 准备本地 SOCKS5 凭据，面板为两个用户配置端口授权。任务 `#2 config.apply` 返回 `SUCCEEDED`。面板接口将用户统计和精确额度均标为 `UNSUPPORTED`。未批准端口的草稿返回 HTTP `409`，已应用修订保持原值。 |
| 订阅与真实连接 | 两个订阅仅返回各自获准的端口。用面板订阅页的生成逻辑和用户持有的密码创建原生 Xray 客户端配置，两个客户端均通过 SOCKS5 取得允许的 HTTP 测试响应。使用另一用户密码的请求被拒绝。 |
| 回滚 | 占用候选监听端口触发 systemd 启动失败，任务 `#3 config.apply` 返回 `ROLLED_BACK`。服务恢复到原配置和修订，两名用户的原客户端均可继续连接。 |
| 撤销 | 撤销订阅令牌后，原链接返回 HTTP `404`，已下载配置仍可连接。任务 `#4 config.apply` 成功移除该用户的节点授权，原客户端随即无法连接，另一用户仍可使用原配置。旧修订的订阅失效，重新签发的订阅返回新修订。 |
| 静态检查与构建 | 本地通过相关 Go 测试、Linux `go vet`、受影响命令构建、协议向量和 shell 语法检查。`ro` 通过 `scripts/check-static.sh`，完成 Master 与 Agent 的 amd64/arm64 安装包构建及 SHA-256 校验。Go `1.27.4`、Node.js `26.13.1`、pnpm `12.17.0`。实际启动和连接验收使用 amd64。 |

客户机输出 `PHASE4_DEMO_PASS` 并正常关机。生产 NTS 服务和签名信任的验收见[第三阶段生产发布验收](./phase-3-release.md#生产发布验收)。

### HTTP 专用入站验收

2026-11-23 在 `ro` 从 `/root/mcui` 建立隔离检出，验证提交 `093b8c25ad6b44f620da75e27c13b3a362cdb8c3`。使用无外网网卡的 Debian 13.7 amd64 KVM/QEMU 客户机，内核 `6.12.107+deb13-cloud-amd64`，systemd `257.13-1~deb13u1`。chrony `4.9` 使用隔离 NTS 和测试 CA。清单和任务使用独立测试密钥签发。制品为上述官方 Xray `v26.10.31` amd64 ZIP，已核对 SHA-256。

| 检查 | 结果 |
|---|---|
| 注册、安装和下发 | 空 Agent 注册成功。`#1 core.install` 和包含两种端口的 `#2 config.apply` 返回 `SUCCEEDED`。未批准端口及类型不符的草稿返回 HTTP `409`。集成测试确认未声明 `xray_http=v1` 的 Agent 不会领取包含 HTTP 专用端口的任务。 |
| 订阅与连接 | SOCKS5 用户取得原格式订阅，拥有 HTTP 专用端口的用户取得带 `http_ports` 的订阅。用两份订阅分别生成原生 Xray 配置并连接批准目标。锁定版的原 SOCKS 端口也通过同凭据的 HTTP 请求验证。 |
| 代理边界 | HTTP 专用端口拒绝 SOCKS5、缺失凭据、错误密码及该端口未授权的用户。测试确认目的主机名、回环地址和未批准的目标 TCP 端口均可在客户机内直连，经过 HTTP 专用端口时请求被拒绝。 |
| 回滚和撤销 | 本地占用候选监听端口，`#3 config.apply` 返回 `ROLLED_BACK`，两个原客户端恢复连接。撤销链接后请求旧订阅返回 HTTP `404`。`#4 config.apply` 移除节点用户授权后，该用户的原客户端无法继续连接，另一用户仍可使用。 |
| 密码轮换 | 节点 root 原子更新目录密码。`#5 config.apply` 返回 `SUCCEEDED` 后，旧凭据被 HTTP 专用端口拒绝，新凭据可连接。 |
| 检查与构建 | 本地通过相关 Go 测试、Linux `go vet`、双架构编译、协议向量、前端类型检查与构建。`ro` 以 Go `1.27.4`、Node.js `26.13.1`、pnpm `12.17.0` 通过 `scripts/check-static.sh`，构建并校验 Master 和 Agent 双架构安装包。运行验收使用 amd64，输出 `PHASE4_DEMO_PASS`。 |

面板将 Xray 用量标为 `UNSUPPORTED`，精确额度禁用。持久化计量和独立凭据管理仍待完成。
