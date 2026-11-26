# Xray 受控入站

2026-11-25 在 `ro:/root/mcui` 的隔离检出验证提交 `0cd92d08741335937c487ea23bed0e9b270d0ef3`。Linux 全量静态检查及 Master、Store、任务投递、Xray 配置与运行时的竞态测试通过。隔离网络使用 SHA-256 核验的官方 Xray `v26.10.31`，实际验证了 VLESS RAW 客户端连接和统计查询。Master、Agent 托管 Core 安装包与双架构成对运行时构建并核对 SHA-256。真实 VLESS 测试在网络命名空间内连接受控入站，公网 systemd 中继由现有运行时检查覆盖。

新节点可使用主控定义入站。节点、Master、Agent、Helper 和独立签发服务须使用支持相应模式的版本。主控 SOCKS5 的安全策略随 Agent 能力版本更新；此轮不包含旧 Agent 兼容或旧节点迁移。

主控定义的 VLESS 入站支持 RAW TCP、WebSocket、gRPC、HTTPUpgrade 和 XHTTP 基础传输，可启用公网 TCP 入口。当前这些主控定义的 VLESS 传输不提供加密，应在可信网络或已有安全传输通道中使用。客户端配置和分享链接使用已生效修订中的传输参数。更新 Agent、Helper 和主控后，节点上报 `panel_public_vless` 才能保存公网入口。TLS、主控定义 REALITY、mKCP、宿主网络直监听及更多高级传输参数仍在开发中。

2026-11-26 使用远程隔离检出与 Xray `26.10.31` 测试了 WebSocket、gRPC（普通与多路）、HTTPUpgrade 和 XHTTP 四种模式的回环数据交换及节点已生效配置对账。此测试不覆盖公网中继、TLS 或 REALITY 组合。

订阅页面可以根据已授权的 VLESS 入站及用户输入的凭据生成 `vless://` 分享链接和二维码。链接包含 UUID，节点目录 REALITY 链接还包含 Short ID，请按凭据保管。回环地址仅在能够访问节点回环网络的环境中有效。此功能参考 [3x-ui v3.11.0 的 VLESS 分享格式](https://github.com/MHSanaei/3x-ui/blob/c621ba9014a6aa21fd7c9ecf45655e44e24ebf13/frontend/src/lib/xray/inbound-link.ts)，不代表其他传输或安全组合已接入。

## 从主控添加入站

1. 主控须配置可从节点访问的 HTTPS 地址及含 Xray 引导的[通用安装包](./phase-1-operations.md#构建包含-xray-引导的安装包)。在「节点管理」添加节点、生成接入命令并在新的 Debian amd64 systemd 节点执行。安装器准备独立网络命名空间和 Helper 的入站凭据解密密钥；节点需要 TUN、网络命名空间及 systemd 地址过滤。等待 Agent 心跳上线并取得可信 NTS 时间，在节点的「管理 Core」中安装官方 Xray `v26.10.31`，等待任务成功及状态上报。
2. 在主控打开「代理配置 → 入站 → 添加入站」，选择 SOCKS5，填写监听端口和客户端用户名，并生成或填写密码。SOCKS5 使用直连公网的 Freedom 出站；Xray 最终出站规则和 systemd 网络策略都会拒绝回环、私网、链路本地、保留和元数据地址。TCP 域名请求会在最终目标检查中解析，SOCKS UDP 关闭。保存前复制凭据。
3. 入站默认仅在隔离网络的回环地址监听。需要远程连接时勾选「启用公网 TCP 接入」，选择节点上报的公网 IPv4 和端口；该 systemd 中继转发到隔离网络中的 SOCKS5 入站。公网 SOCKS5 是未加密 TCP，用户名、密码和代理流量都可被链路观察，请放在可信网络或另加受保护隧道。
4. 保存后等候节点预览。核对 SHA-256，确认下发并按提示完成 MFA。以任务成功和节点上报的修订号确认生效。可编辑用户名、凭据或公网入口，也可删除后下发；凭据留空会保留原值。

SOCKS5 使用隔离网络内的 slirp4netns DNS 转发器解析 IPv4 域名，要求节点的上游 DNS 可用。DNS 请求走专用路由，代理请求仍在解析后检查最终目标。公网入口要求节点实际绑定所选公网 IPv4；NAT 地址、IPv6 公网监听和 SOCKS UDP 不属于本次流程。主控入站配置目前只支持上述 amd64 Xray 版本。此流程面向新节点，不包含旧节点兼容或迁移。

可用 `curl --socks5-hostname <节点公网IPv4>:<公网端口> --proxy-user '<用户名>:<密码>' https://example.com/` 验证域名代理；在可信终端执行，避免泄露凭据。失败时先检查节点心跳、Core 安装及配置任务、NTS 同步、DNS、云安全组和宿主防火墙，再检查 `mcui-xray-network.service` 与 `mcui-xray.service` 的日志。

2026-11-25 在 `ro` 的 Linux amd64 临时检出验证本轮 SOCKS5 修复：`scripts/check-static.sh` 通过；使用 SHA-256 核对为 `e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214` 的官方 Xray `v26.10.31`，在隔离命名空间验证认证、IPv4 和域名转发，以及阻止连接可达的模拟元数据地址。另以 slirp4netns 1.2.1 和同一生成配置，通过 SOCKS5 域名请求取得公网 HTTPS 响应；以临时 systemd 单元核对地址策略加载和显示格式。本轮真实网络验证针对 SOCKS 数据面；节点接入、Core 安装和签名下发仍由现有集成测试及上文历史验收覆盖。

支持多客户端的节点在入站表单显示「添加客户端」。同一入站最多八名客户端，仍受节点总授权数和签名草稿大小约束。新增客户端填写独立凭据，编辑时留空保留原凭据。已在「客户端」页绑定的账号从该页解绑或轮换，其他账号可直接在入站表单编辑。下载公网 Trojan 配置时选择对应客户端。已有单客户端草稿可直接编辑。

在主控入站列表选择「复制」，可在同一节点创建一个新端口，沿用源入站的协议、客户端名称和路由顺序。为新端口的每个客户端生成或填写独立凭据并在保存前交付。公网接入需为新端口重新选择。复制保存的是草稿，确认下发后生效。若要把客户端纳入主控订阅，再到「客户端」页绑定新入站。

每节点最多四个此类入站。回环入站监听在隔离网络的 `127.0.0.1`，启用公网接入的 Trojan 通过 `127.0.0.2` 接收中继连接。节点依托系统 TUN 和 slirp4netns 向选定目标转发。主控草稿、签名任务和审计使用加密凭据或操作元数据，Helper 在节点本地解密。

入站保存后，可在同一节点的「出站」设置最多四个 Freedom 出站，每个指定一个明确的公网 IPv4 和 TCP 目标端口。再在「路由」为入站选择出站。支持多条规则的节点可以为同一入站配置多个目标并调整顺序，也可让多个入站共享同一出站。入站表单显示这些目标，放行规则通过「路由」编辑。没有匹配规则的流量走默认拒绝。保存、预览并完成 MFA 下发后，以节点上报的修订确认生效。

### 从主控开通 Trojan/TLS 公网入口

1. 添加 Trojan/TLS 入站并勾选「启用公网 TCP 接入」。选择节点上报的已绑定公网 IPv4，填写外部端口（例如 `443`）。隔离网络中的入站端口与外部端口分别设置。客户端所在的网络须能访问该节点的 TCP 端口。
2. 保存、预览并完成 MFA 下发。主控为节点生成一个 90 天有效的 `localhost` TLS 证书，节点的主控 Trojan 入站共用该证书。Helper 应用配置后启用临时 systemd TCP 中继。停止 Xray 或撤销公网入口会关闭相应的套接字，启动时恢复已提交的入口。端口占用导致应用失败时会恢复上一版配置、地址许可和监听。
3. 任务成功且节点上报对应修订后，在入站行点击「客户端配置」，输入此前复制的密码，下载 `xray-client.json`。主控仅使用已签发并经节点确认的证书和端点生成文件。客户端用该证书验证 `localhost`。也可签发单节点订阅，由接收者输入相应密码。
4. 轮换时编辑任一主控 Trojan 入站，勾选「轮换此节点主控入站共用的 TLS 证书」，再预览及下发。新证书生效后，更新该节点所有 Trojan 客户端的配置。

在「客户端」页可将主控定义的入站与其他节点的入站绑定到同一主控客户端，也可轮换凭据并签发领取链接。[客户端订阅](#客户端订阅)

2026-11-24 在 `ro` 的隔离 Debian 13 amd64 QEMU 客户机验收。无外网网卡，以独立的外部客户端命名空间模拟连接宿主公网 IPv4。官方 Xray `v26.10.31` 制品经 SHA-256 校验。真实客户端通过临时 systemd 中继连入 Trojan，读取批准目标，错误密码和未批准目标均被拒绝。占用新外部端口后，下发返回 `ROLLED_BACK` 并恢复原入口。证书轮换后信任旧证书的客户端连接失败，信任新证书的客户端恢复连接。停止 Xray 释放宿主端口，重新启动恢复原入口。主控签发及订阅元数据校验另由集成测试覆盖。

### 主控定义入站验收

2026-11-24 在 `ro` 使用无外网网卡的 Debian 13 amd64 QEMU 客户机、Linux `6.12.107+deb13-cloud-amd64`、systemd `257.13` 和 slirp4netns `1.2.1`。Xray 使用官方 `v26.10.31` Linux amd64 ZIP，已按发布摘要核对 SHA-256。

- 主控集成测试覆盖首次绑定节点公钥、凭据密文持久化、独立检查点、预览前拒绝签发、双签名绑定及旧 Agent 拒领。配置测试覆盖密文无法转用其他节点或客户端、禁止私有目标。
- 在客户机中应用真实 SOCKS5 入站。正确凭据能访问指定 IPv4 TCP 目标，另一可达目标和错误凭据均被拒绝。候选端口被占用时，新修订返回 `ROLLED_BACK`，旧客户端连接和原 systemd 地址许可恢复。签发流程通过集成测试验证，实际连接从已签名配置所用的节点运行时入口验收。

## 将旧节点迁移到主控定义模式

1. 为 Debian amd64 节点安排维护窗口。保护性备份主控数据库、任务库，以及节点的 Agent、Helper、Xray 状态和旧版 systemd 配置。记录需要在主控重建的入站和客户端。
2. 解除该节点的主控客户端绑定，撤销旧分享并将节点预配草稿清空。等待空修订生效，再从面板卸载 Xray。等待卸载任务成功、心跳确认未安装后，将旧 `controlled-inbound.json`、`managed-inbounds.json` 和旧版手工转发或网络配置归档至 root 私有目录，并停用旧版手工公网套接字。
3. 按原节点 ID 补发接入命令。使用含 Xray 引导且已验证摘要的安装器，在调用时同时带上 `--preserve-state` 和 `--enable-panel-inbounds`。安装器保留 Agent/Helper 账本、已接受的制品清单及 Xray 修订序号。首次切换时若检测到仍安装的 Xray、未决事务或旧策略文件，安装器会中止迁移初始化。
4. 等待同一节点上报后，从主控重新安装 Xray、创建入站、签发配置并重建客户端绑定。迁移需要重建授权及客户端配置。后续配置应用失败时，节点按已提交修订恢复。

保留迁移备份和原发布材料，旧策略恢复按节点状态与主控账本连续性核对后执行。 [节点接入和恢复](./phase-1-operations.md#轮换禁用与旧节点迁移) · [防回退](./agent-protocol.md#6-防回退与灾难恢复)

### 安装与迁移验收（2026-11-24）

提交 `a299468486dbe9b406fae03d50048afa5e9fbc28` 在 `ro` 的隔离检出通过 `scripts/check-static.sh`，主控、成对更新、Xray 配置和运行时的竞态测试通过。Master、Runtime 和 Agent 双架构构建及 SHA-256 校验通过。Agent 分别构建基础包、成对运行时引导包，以及同时含 Xray 与成对运行时的引导包。

在无外网网卡的 Debian 13 amd64 QEMU 客户机，实际安装器经回环 HTTPS 接入测试主控。首次兑换失败后用同一个安装包成功重试。Agent 和 Helper 由 systemd 从同一不可变版本指针启动，重启后基线不变。保留状态迁移在旧策略文件存在时拒绝，归档旧策略后使用原节点 ID 成功接入。两份任务账本、运行时版本指针保持原状，节点上报主控定义模式的公钥。Linux 运行时测试另核对卸载后迁移保留既有 Xray 修订水位。

在同一客户机使用经 SHA-256 校验的官方 Xray `v26.10.31`，通过节点运行时应用 SOCKS5 入站，实际连接取得批准目标的 HTTP 响应。占用候选端口后，应用返回 `ROLLED_BACK`，对账重读同一结果，旧修订、原地址许可和客户端连接均恢复。停止 Xray 后旧客户端无法连接，重新启动后恢复。主控签发和配置投递由 Linux 集成测试覆盖。

## VLESS、VMess 和 Shadowsocks 2022

这些模板适用于 Linux amd64 的 Xray `v26.10.31`，沿用节点预配端口及用户授权。监听地址固定为专用命名空间的 `127.0.0.1`，业务路由只允许节点批准的字面 IPv4 和 TCP 端口。启用前更新 Master、独立签发服务、Agent 和 Helper。

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

### 公网 TCP 入口隔离验收

2026-11-23 在 `ro` 从 `/root/mcui` 建立隔离检出，验证提交 `cf724c86da6152db4786849e3c357269c1c5ecb2`。使用无外网网卡的 Debian 13.7 amd64 QEMU 虚拟机，内核 `6.12.107+deb13-cloud-amd64`，systemd `257.13-1~deb13u1`，以及已核对 SHA-256 的官方 Xray `v26.10.31` amd64 制品。虚拟网卡模拟绑定于宿主网络的公网 IPv4，测试客户端和 Xray 分别使用独立且无默认路由的网络命名空间。

| 检查 | 结果 |
|---|---|
| systemd 单元校验 | Helper 的配置检查在真实 systemd 上接受正确的监听和转发单元，拒绝绑定到另一 IPv4 的套接字。 |
| 协议和路由 | 用订阅页共用逻辑生成两种原生 Xray 客户端配置。授权的 Trojan/TLS 和 VLESS/REALITY 客户端经套接字转发取得批准目标的 HTTP 响应。未授权账号和未批准的目标 TCP 端口均被拒绝。访问 REALITY 入口的普通 HTTPS 请求取得专用命名空间内固定 TLS 应答端的响应。 |
| 恢复回环监听 | 改用在同一节点端口监听的回环 SOCKS5 配置后，命名空间内的认证客户端仍能访问批准目标。保持原公网套接字运行，外部客户端无法通过它连接回环 SOCKS5 服务。 |
| 静态检查与构建 | `scripts/check-static.sh` 通过，Agent 安装脚本和 Master 的 amd64/arm64 安装包完成构建及 SHA-256 校验。真实数据面在 amd64 验证。 |

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
3. 在节点列表打开该节点的「代理配置」，在页头的「Core 类型」选择已安装的 Xray。在「入站」展开端口行的「查看与编辑」，勾选允许的用户后保存草稿。未授予用户的端口不监听。最多启用 4 个端口、登记 8 个用户名并同时分配 16 条端口授权。用户名以小写字母开头，最多 24 个字符，可含小写字母、数字、连字符和下划线。
4. 在「客户端」也可以按用户名管理该客户端的入站授权，并前往「客户端订阅」。等待节点心跳后，在「预览变更」对照生效配置与草稿，核对端口类型、出站、路由和节点报告的 SHA-256。「确认下发」提交任务，按提示完成 MFA 复验。签发后草稿可以继续编辑，已签发任务仍按当时批准的配置执行。以成功任务及节点上报的已应用修订确认变更生效。
5. 撤销授权时取消对应选项并重新下发。保存并应用空草稿会移除全部监听。轮换密码时由节点 root 原子更新目录文件，通知客户端，再用相同授权重新预览并下发新摘要。修改 `http_ports` 后等待心跳并重新保存草稿。仅编辑草稿或节点文件不会中断当前连接。应用配置会重启运行中的 Xray，撤销从成功应用的新修订开始生效。

节点目录存在时启用面板管理模式。移除该文件后可由原单用户模式准备并签发新的配置，当前已提交配置仍可运行。目录读错、端口类型或摘要不匹配时停止下发该候选，保留上一次提交的配置。密码由节点 root 保管，通过部署方的安全渠道交给授权客户端。启用 `http_ports` 前，先更新 Master、Agent、Helper 和独立签发服务。

### 自定义出站与路由

1. 将 Master、独立签发服务、Agent、Helper 和 `mcui-xray` 更新到支持自定义路由的同一版本。在节点的 `managed-inbounds.json` 添加 `routing_destinations`，最多列出四个批准的公网 IPv4 TCP 端点，每项使用 `address` 和 `port`。保留 `destination_ip` 和 `destination_port` 作为默认模式的目标。若自定义模式也要访问该目标，将它列入 `routing_destinations`。
2. 为每个批准地址在 Xray 的 `IPAddressAllow` 中加入相应的 `/32`，同时配置命名空间路由及防火墙，再执行 `systemctl daemon-reload`。保留现有生效配置的网络许可，直到新配置成功应用。
3. 在「出站」启用自定义配置，为选中的目标添加 Freedom 出站。在「路由」为已获客户端授权的入站添加规则，并选择目标出站。每条规则匹配该入站、目标 IPv4 和 TCP 端口，未匹配的流量交给默认的 `deny` 出站。没有放行规则的自定义配置会拒绝全部业务流量。移除某个入站的最后一条客户端授权时，草稿同时移除该入站及其路由。
4. 保存草稿，等待节点预览，再核对并下发。若要恢复默认模式，在「路由」或「出站」选择「恢复节点默认路由」，保存并签发新修订。

在「路由」可选择入站并输入目标 IPv4 和 TCP 端口，点击「测试草稿路由」。面板按草稿中的规则顺序显示首条匹配规则及对应出站，没有匹配时显示默认拒绝。测试根据当前编辑的草稿计算，无需下发配置，也不会发起网络连接。

## 节点本地单用户模板

首个模板适用于 Linux amd64 的 Xray `v26.10.31`，仍需匹配独立签名稳定清单中的精确制品。节点本地 root 审批监听端口、密码和单一 IPv4 TCP 目标。面板管理员只审批候选端口和配置指纹。模板固定用户 `mcui`、回环监听、密码认证及默认拒绝路由。[配置策略](./config-policy.md) · [Xray SOCKS 文档](https://xtls.github.io/config/inbounds/socks.html)

## 节点准备

1. 部署使用同版程序的 Master 和签发端。Debian 节点可以执行[带 Xray 引导的 Agent 安装命令](./phase-1-operations.md#构建包含-xray-引导的安装包)，上线后从主控安装清单批准的 `v26.10.31`。手工部署按[阶段 3 操作手册](./phase-3-operations.md)安装 Agent、Helper、`mcui-xray` 和 Xray units。手工更新已有节点 unit 后运行 `systemctl daemon-reload` 和 `mcui-xray recover`。
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

1. 等待节点心跳刷新。在「代理配置」选择 Agent 和已安装的 Xray，再打开「预览变更」，核对候选端口和 SHA-256，确认下发并完成当前 MFA。下发要求当前任务绑定的版本和摘要与节点状态一致，并且节点汇报的候选内容有变化。
2. 在「代理配置」查看最近下发和上报修订，或从「设置 → 任务」查看回执。运行中的节点切换时会重启 Xray。原先已停止的节点会短暂启动候选作健康检查，然后恢复停止状态。
3. 让测试客户端在同一专用命名空间中访问 `127.0.0.1:<监听端口>`，用用户 `mcui` 和本地密码请求批准的字面 IPv4 与端口。分别验证错误密码、目标端口不匹配和域名请求被拒绝。客户端测试凭据使用受限权限的本地配置文件传入。
4. 配置预检、策略摘要或授权校验失败时，任务返回 `FAILED`。候选启动失败且成功恢复时返回 `ROLLED_BACK`。未决事务用原签名任务对账，必要时由节点 root 执行 `mcui-xray recover`。移除候选策略文件会阻止新的下发。停用运行中的入站可在面板停止 Xray。跨版本切换成功后使用新版本的引导配置。

面板显示候选和已应用配置的摘要、端口及修订号。节点配置和密码保存在节点的私有目录。[阶段路线图](./phased-development-workflow.md#阶段-4xray-完整业务闭环与最小演示)

## 客户端订阅

1. 在侧栏「客户端」创建一个主控用户名。在「分配入站」选择节点、端口及凭据名。节点预配模式使用目录中登记的凭据名。主控定义模式使用入站草稿中的用户名。同一个主控用户可以绑定两种模式的多个节点。同一个节点的凭据名只分配给一个主控客户端。
2. 在支持多客户端的主控定义节点，选择现有的节点凭据名，也可选择为当前主控客户端生成凭据。同一次保存可分配多个节点，并在「分享」中显示分别签发的短期领取链接。到有配置变化的节点预览并下发，等待成功任务和对应心跳后再领取。绑定已有凭据沿用当前草稿和应用状态。解绑仅撤销所选凭据的授权，移除主控定义入站的最后一名客户端时同时移除该入站和对应路由。节点预配模式按节点目录中的授权工作。
3. 打开该用户的「分享」，签发一条总订阅以及各已生效入站的分享链接。链接最长有效 30 天，可复制和扫码，可单独签发、轮换或撤销一个入站的链接。链接正文在签发后保留于当前页面内存，主控只保存摘要。整个客户端的轮换或撤销会使之前签发的对应链接失效。
4. 用户在浏览器打开 HTTPS 链接。总订阅列出当前已生效的节点、入站和协议，单入站链接仅列出一个入口。选择入口后输入管理员交付的协议凭据，浏览器在本地生成包含该凭据的 `xray-client.json`。使用 `xray run -config xray-client.json` 启动。回环入口需要客户端能够访问节点的相应回环地址。

在「客户端」可删除账号。删除立即撤销该账号的订阅和领取链接，并在各绑定节点的草稿中移除相应授权。需要逐节点预览及下发，节点应用新修订后原凭据才失效。

总订阅每次拉取根据当前绑定重新确认生效状态，节点离线、Xray 停止或有未决生命周期任务时暂时省略该节点。新增绑定生效后从同一总订阅领取。解除绑定会立即移除其订阅项和单入站链接，已下载配置的连接权限在节点应用撤销或轮换对应凭据后失效。旧单节点订阅仍沿用原修订及到期规则，可从节点代理配置的「客户端 → 旧订阅」管理。

新链接使用 `/subscription/client`，浏览器把 URL 片段中的令牌放入 `Authorization: Bearer` 请求 `GET /api/v1/client-subscription`。响应的 `entries` 包含节点 ID、名称及各入站的配置元数据。每个条目的 `config` 复用 `GET /api/v1/subscription` 的旧元数据格式，版本 1 对应 SOCKS，版本 2 包含 HTTP 专用端口，版本 3 通过 `port_protocols` 描述其他协议，版本 4 附带 `public_endpoints`。Trojan 的公开证书与 REALITY 公钥按入站返回。两个 API 共用来源限流且禁用响应缓存。反向代理须避免记录 `Authorization` 请求头和签发响应正文。恢复备份后，使用独立检查点核对撤销状态，或由管理员复核并撤销恢复的链接后再开放订阅端点。

### 轮换和交付主控凭据

1. 在客户端的「分享」中，选择一个已绑定的主控定义入站，点击「轮换凭据并生成领取链接」并完成 MFA。主控按协议生成密码或 UUID。领取链接在当前页面显示，有效期为 24 小时，需通过可信渠道交付。
2. 打开该节点的「代理配置」，预览并下发新草稿。任务成功且节点上报对应修订后，旧凭据失效，领取链接可用。若应用回滚，节点保留旧凭据，领取链接暂不可用。
3. 收件人在 HTTPS 页面打开领取链接，可直接下载客户端配置，并展开「查看本地 SOCKS5 凭据」配置使用该客户端的程序。领取链接只覆盖一个入站，普通订阅和分享链接依然需要输入凭据。再次轮换、撤销该入站的链接或解除绑定会使原领取链接失效。

节点草稿只保存节点公钥加密的凭据。主控另外保存领取令牌的摘要和用独立派生密钥加密的交付密文。在签名任务和节点上报均确认同一加密凭据后，领取请求才返回明文。反向代理须对该响应禁用正文记录。已经下载的配置包含凭据，需按密码管理。

### 跨模式订阅回归（2026-11-24）

提交 `bd3af2af7c8ab31c4041f0eb092e89e96d701c50` 在 `ro` 的 Debian amd64 隔离检出通过 `scripts/check-static.sh`，并完成 Master、Agent 和 Runtime 的 amd64/arm64 打包与 SHA-256 校验。集成测试覆盖节点预配与主控定义的入站共用总订阅、待应用入口隐藏、签名证书与端点绑定、单入站分享和解绑即时撤销。

凭据交付提交 `ae1982102b533131e1dc1b315f3533dee70ea2d4` 在相同环境通过全量检查、Master 和 Agent 构建及摘要校验。集成测试核对待应用链接不可领取、成功任务仍须等待对应心跳、普通分享保持仅返回元数据、数据库和管理响应未保存或返回明文凭据，以及解绑立即撤销领取权限。

路由提交 `135bb389da18038a551b19d4602d96ed82b82dea` 在 `ro` 通过相同检查和打包。仅回环网络命名空间内使用核对 SHA-256 的官方 Xray `v26.10.31`。服务端配置由签发集成测试的草稿渲染，客户端使用浏览器共用生成器读取已领取的凭据。真实 Trojan/TLS 连接可到达唯一放行的 IPv4 TCP 端点，能直连的备用出站目标被拒绝。新凭据应用后旧凭据失败，进程重启后新凭据仍可用，应用解绑修订后连接失败。此轮以测试 TCP 中继模拟公网套接字。

### 订阅验收记录（2026-11-23）

在 `ro` 从 `/root/mcui` 建立 Debian 13 amd64 隔离检出，验证提交 `579c84f`。集成测试覆盖管理员节点范围、CSRF、MFA、摘要落盘、审计脱敏、拉取端口隔离、到期、轮换、撤销、限流，以及已签名任务与节点快照不一致时暂停拉取。

在无默认路由的隔离网络中，用浏览器页面共用的生成器输出客户端配置，核对上游 ZIP 摘要后使用真实 Xray `v26.10.31` 运行服务端和客户端。两名授权用户均通过自己的原生客户端访问测试目标，缺少或输错本地密码时被拒绝。重启服务端应用移除授权的配置后，旧客户端连接失败，其余用户仍可连接。

同一提交通过 `scripts/check-static.sh`，主控、存储、任务投递和 Xray 配置的竞态测试，以及 Master amd64/arm64 安装包构建和 SHA-256 校验。

## 用户级统计与额度

主控定义模式支持按当前生效修订采样。先更新 Master、独立签发服务、Agent、Helper 和节点的 Xray systemd 单元。在运行中的 Debian amd64 节点打开「代理配置 → 流量」，选择「在草稿中启用统计」，预览后完成 MFA 并下发。运行时用专用组保护的 Unix socket 查询 Xray `StatsService`。面板显示入站、客户端和出站各自的上行与下行累计、采样时间及状态。

主控按节点、修订和进程实例计算增量。重复采样不会增加累计。Xray 重启后累计已采集的流量并标记可能存在缺口。主控离线期间，仍可从持续运行的 Xray 读取累计计数。停用统计、启用新修订或未收到当前修订的样本时，页面显示对应状态。已采样的客户端显示 `SAMPLED`。在「客户端」列表可查看各节点当前修订的已知用量合计。同一节点的同一账号即使绑定多个入站也只计一次。样本缺失、过期或有缺口时，界面会标明覆盖情况。跨修订历史、节点离线队列、周期重置和精确额度待实现。

在「流量」页可对单个入站、客户端或出站的已采样累计点击「清零」。清零基于当前显示的样本，遇到新样本时需要刷新后重试。节点上次采样之后产生的流量在后续采样中计入清零后的累计。客户端按节点分别清零，客户端页合计随之更新。

现有节点若仅更新 Agent/Helper 二进制，另须应用新安装器中的 Xray 网络及 Helper 单元配置，并创建专用系统组 `mcui-xray-stats`。在维护窗口重载 systemd 并重启相关单元。统计端点由 Xray 服务创建在 `/run/mcui-xray-stats/`，Helper 属于同一专用组。节点目录模式继续使用原配置。

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

两种模式下均验证了 Alice 与 Bob 的计数互不影响、拒绝认证不计量，以及重复查询不重置计数。重启后查询为空。禁用 `splice` 的结果仅证明这组样本的连接内读数。当时的面板显示 `UNSUPPORTED`，未知用量留空。

同一提交通过 `scripts/check-static.sh`、面板 Xray 竞态回归，以及 Master amd64/arm64 安装包构建和 SHA-256 校验。

2026-11-24 在 `ro` 的仅回环网络命名空间用同一摘要的官方制品重测，得到相同的连接中、关闭后和重启读数。重启前未采集的用量仍无法从 Xray 补回。面板继续禁用精确额度。

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

该轮 HTTP 入站验收时，面板将 Xray 用量标为 `UNSUPPORTED`。后续统计能力见[用户级统计与额度](#用户级统计与额度)。

### 多客户端、多路由与流量验收（2026-11-24）

从 `ro:/root/mcui` 的仓库建立隔离检出，验证代码提交 `a4137c5a9311f5882e59440a8c5c58704e8c2d4d`。使用 Go `1.27.4`、Node.js `26.13.1` 和 pnpm `12.17.0`。

| 检查 | 结果 |
| --- | --- |
| 检查与构建 | 本地通过 Linux `go vet`、amd64/arm64 交叉构建、相关 Go 测试和前端构建。`ro` 通过 `scripts/check-static.sh` 和定向竞态测试，完成 Master、成对运行时及带 Xray 引导的 Agent 安装包构建与 SHA-256 核对。 |
| 签发与下发 | 在多客户端入站上验证独立的凭据生成、轮换和解绑。应用测试验证同一入站的多条路由、旧 Agent 拒领以及配置变更保留其他客户端。 |
| 流量汇总 | 续用同一进程的累计样本不会重复计数，进程重启标记采样缺口。面板竞态测试验证跨节点合计，并确认同一节点账号绑定多个入站时只计一次。 |
| 真实 Xray | 在仅回环的网络命名空间用经 SHA-256 校验的官方 `v26.10.31` 运行 SOCKS5，采集器读到入站、客户端及出站字节。双客户端探针再次确认默认 `splice` 在连接结束后补齐下行读数，禁用 `splice` 后连接中可见，重启清空 Core 计数。 |
| 套接字隔离 | 临时 systemd 单元启用动态用户、专用组和私有网络。实测目录权限为 `0750`，套接字为 `0660`，组内的独立进程可读取统计。 |
