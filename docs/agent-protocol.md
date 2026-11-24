# Agent 身份、任务与配置协议（阶段 0 冻结基线）

> 状态：阶段 0 已冻结 V1 签名编码与一般任务、序号和恢复语义基线，等待项目内安全检查。阶段 2 以 V2 接通只读状态查询，并复用 V1 独立域实现受限取消与跳过。阶段 3 显式启用的节点可执行远程 Xray 安装，其他远程变更仍在规划中。本文细化[分阶段流程](./phased-development-workflow.md)与[Agent 技术设计](./agent-technical-design-v1.0.md)。
> 节点接入部署与旧节点迁移见[阶段 1 运维手册](./phase-1-operations.md)。

## 1. 信任边界与基本约束

Agent 主动 HTTPS Pull，任务投递和 ACK 按节点 Token 鉴权。Master 从凭据记录确定节点，逐请求检查当前状态与对象归属。Master Web、Signer、Agent、root Helper、Core 为独立边界。当前状态任务 Signer 使用专用 Ed25519 私钥签署 V2 `core.status`。制品发布、节点凭据和任务密钥相互独立。Web 不直接持有签名私钥。Master 对只读查询逐请求校验管理员角色和节点范围并写审计。高危任务按[面板授权](./panel-authz.md)执行。节点的制品发布公钥通过带外配置更换。审批绑定操作、节点、规范化参数摘要、期限和用途，`approval_id` 索引对应的签名授权证据。

任何签名都不能代替配置语义策略、可信制品验证或 Helper 独立授权。禁止任意 Shell、脚本、URL、文件路径、unit 和 argv；未知类型、字段、策略一律拒绝。主控离线或认证失败时不接收新授权，默认保留运行中的 LKG；已开始事务只能依照下文恢复。完全控制合法签名者或节点 root 仍可能破坏安全。

## 2. 节点接入、Token 轮换和撤销

1. **添加节点。** 有目标组权限的安全管理员先在主控添加节点。Master 分配不可复用的 `node_id`，初始显示「待接入」。生成命令时校验该节点的管理权限和 MFA 复验，签发绑定该已启用节点的短期一次性安装码。同一节点只保留最新的未兑换安装码；生成、兑换、拒绝、轮换及撤销均记录脱敏审计。
2. **连接主控。** Agent 安装程序与 Agent 连接配置的 Master 地址时使用 TLS 1.3，校验服务端证书链、有效期和主机名，默认使用系统 CA，私有 CA 通过本地受信配置提供。请求不跟随重定向。任务和配置验证公钥及其 key ID 通过独立可信渠道引导。Helper 租约检查点使用相同的服务端证书验证方式，继续校验原始签名任务与精确租约。
3. **兑换凭据。** `POST /api/v1/agent/enroll` 使用 JSON `{"install_code":"..."}`。Master 校验安装码摘要、用途、有效期及关联节点的启用状态，在同一事务中消费安装码、登记新 Token 摘要并使原凭据失效。并发兑换至多成功一次，过期、已使用或被替换的码均拒绝。成功返回 HTTP 200 和 JSON `{"node_id":"...","node_token":"..."}`，凭据响应禁止缓存。兑换按来源限流。响应丢失或本地未保存成功时，由管理员为原节点重新生成命令。
4. **持续认证。** 安装码与节点 Token 分别用密码学安全随机源生成，Token 至少含 32 字节随机数据。主控仅存摘要，安装程序原子写入仅 Agent 账户可读的 Token 文件。随后每次 Agent API 请求携带 `Authorization: Bearer <node_token>`。Master 按 Token 摘要解析唯一节点，逐请求检查启用、撤销及任务/配置归属。请求字段中的 `node_id` 仅用于一致性检查。首次有效心跳使原节点上线。安装码和 Token 禁止进入 URL、常规日志、审计详情和错误内容。节点 Token 的权限限定为该节点的 Agent API。
5. **轮换与恢复。** 为原节点重新生成命令，成功兑换时使旧 Token 立即失效。发现泄露时可立即禁用节点，同时撤销未兑换安装码和 Token，并停止签发及投递。通信失败或节点被禁用时，已运行的 Core 默认维持 LKG。节点重装时仍按第 6 节确认账本连续性后才恢复任务执行。
6. **现有节点迁移。** 为现有 `node_id` 生成安装命令，保留 Master、Agent 和 Helper 原有任务账本、序号及配置状态。升级后的 Master 停用旧 CSR、客户端证书和邀请认证。现有节点成功兑换新 Token 后恢复通信。状态连续性无法确认时按第 6 节隔离恢复。

Master 地址、显式私有 CA 和任务/配置验证公钥的变更通过受信配置更新流程授权和分发。公有 CA 签发的服务端证书可随主机名正常续期。

默认心跳/任务轮询 15 秒、在线超时 60 秒，随机抖动和指数退避；大小、超时、并发应有限制。服务端时间无法可信判断、明显回拨或超出允许偏差时拒绝新任务/配置并告警，不关闭校验。各端与受信时间源最大偏差定为 30 秒；过期检查不延长期限，恢复事务不依赖重新打开过期授权。

支持主控多客户端入站的 Helper 在 Xray 清单中上报 `panel_multi_client`。Agent 拉取任务时通过 `xray_panel_multi_client=v1` 声明支持。主控定义草稿的密文凭据按入站端口及入站内的用户名顺序排列。单客户端草稿保持原编码。多客户端草稿只投递给声明支持的 Agent。

## 3. 通用签名编码与校验

V1 **仅使用 RFC 8785 JCS + 标准 Ed25519（RFC 8032，非 Ed25519ph）**。所有签名对象是 UTF-8 JSON，最外层 `signature` 为 64 字节签名的 RFC 4648 标准 Base64，保留 `=` padding；公钥是 32 字节原始 Ed25519 公钥。待签名输入为对应 ASCII 域字符串（包含末尾单个 `\n` 字节）拼接 `UTF8(JCS(删除顶层 signature 后的完整 JSON 对象))`，无 BOM、无额外换行、无预哈希。域分别为 `MCUI-TASK-V1\n`、`MCUI-CONFIG-V1\n`、`MCUI-CANCEL-V1\n`、`MCUI-SKIP-V1\n`。签名覆盖 `schema_version`、key ID、算法及所有其他字段；验签按对象种类固定域，不接受消息指定域或算法协商。

JSON 必须符合 I-JSON/JCS：UTF-8 严格解码，拒绝重复键（包括转义后同名）、无效 Unicode/孤立代理、非有限数、未知字段、null、类型错误或尾随数据；不得先归一化 Unicode。所有数字只允许 JSON 整数且在 0..9007199254740991 范围内，计数从 1 开始，禁止指数、小数形式；必须检测溢出。时间仅允许 UTC `YYYY-MM-DDTHH:MM:SSZ`，严格验证日历，不接受闰秒、偏移或小数秒。标识符除另述外使用 1..128 字节 ASCII `[A-Za-z0-9._:-]`；摘要为小写 64 位十六进制 SHA-256。签名 Base64 必须规范解码且长度准确。消息上限 64 KiB；配置原始字节上限 4 MiB。对所有对象必须验证版本为整数 `1`、`signature_algorithm` 精确为 `Ed25519`，并用受信任且具相应用途的 `signing_key_id` 查本地公钥；未知、撤销或不适用的 key 拒绝，严禁从消息自行取得信任。

时间满足 `issued_at <= not_before < expires_at`，接收时拒绝超过本地时间 30 秒的未来 `issued_at`；开始新操作须本地时间不早于 `not_before` 且严格早于 `expires_at`。本地时间无可信依据时暂停。消息先结构解析、校验签名、目标、密钥用途、时间和策略，再持久化和执行；未经认证或不合法的数据不能改变序号或状态。

## 4. 任务、配置和控制消息

以下对象所有列出字段均必填、无其他字段；字段名大小写敏感。每个任务 `task_id` 全局唯一，`node_id` 精确匹配本机；每节点序号自 1 连续分配。定义任务 body（示例未包含可用签名，**不是测试向量**）：

```json
{"schema_version":1,"task_id":"task-001","node_id":"node-001","sequence":1,"operation":"core.start","issued_at":"2026-11-16T08:00:00Z","not_before":"2026-11-16T08:00:00Z","expires_at":"2026-11-16T08:10:00Z","payload":{"core":"xray"},"approval_id":"approval-001","signing_key_id":"task-key-01","signature_algorithm":"Ed25519","signature":"<base64>"}
```

通用字段按第 3 节；`operation` 和 `payload` 严格对应且禁止扩展。`core` 仅 `xray`、`sing-box`、`mita`。V1 已定义以下结构；具体操作及 Helper 步骤未完成安全策略和实测前不得启用：

| operation | payload 必填字段（除 core 外） |
|---|---|
| `core.status` | 无；V1 仅定义签名结构，阶段 2 的运行时使用 V2，规则见[状态任务协议草案](./phase-2-protocol-draft.md) |
| `core.start`, `core.stop`, `core.uninstall` | Xray 使用已安装的 `version`、`architecture`、`sha256`。仅有 `core` 的旧信封保留解析兼容。 |
| `core.restart` | 无 |
| `core.install` | `version`、`artifact_id` 为标识符，`manifest_version` 为正整数 |
| `core.upgrade`, `core.downgrade` | Xray 同时绑定已安装的 `current_version`、`current_sha256` 和目标的 `version`、`artifact_id`、`manifest_version`。旧信封保留解析兼容。 |
| `config.apply` | 当前 Xray 模板使用 `version`、`architecture`、`sha256`、`manifest_version`、`port`、`config`。历史 `revision`、`content_sha256`、`core_version` 形态保留解析兼容。 |

任务签名只授权固定动作；制品 ID、版本、架构及摘要须匹配独立受信任且未过期的发布清单，降级须独立授权。任务时间为启动与新步骤授权边界，不是可无限续租的通行证。[Agent/Helper 成对更新](./phase-3-runtime-update.md)使用本地监督器和独立签名授权。节点 Token 轮换按第 2 节接入流程处理。

**配置签名对象**必填字段：`schema_version`、`node_id`、`core`、`core_version`、`revision`、`content_sha256`、`content_size`、`issued_at`、`not_before`、`expires_at`、`signing_key_id`、`signature_algorithm`、`signature`。通用 `content_size` 上限为 4194304 字节，当前 Xray 模板只接受 1..8192 字节。摘要覆盖精确原始配置字节。

Xray 任务的 `payload.config` 是独立签名的配置元数据。它与任务共用独立 Xray 运维公钥，分别使用 `MCUI-CONFIG-V1` 与 `MCUI-TASK-V1` 签名域。两份签名的节点、Core、精确版本、时间窗与密钥必须一致，配置 `revision` 等于任务 `sequence`。支持 `xray_config=v1` 且使用签名发布清单的 Agent 才能领取此形态。配置正文按节点 root 策略确定性生成，摘要、长度与监听端口均须匹配。Helper 持久化已进入切换的最高修订，配置失败恢复上一次已提交的精确内容和运行意图。通过原任务凭证对账，重复投递不重新应用。要恢复更早的配置需发起更高修订。 [受控入站部署](./phase-4-xray-inbound.md)

面板管理配置任务另含外层签名字段 `payload.plan`。其值是紧凑 JSON 字符串，内含按端口升序排列的对象。原模板使用 `{"port":1080,"users":["alice","bob"]}`，节点明确授权的 HTTP 专用端口使用 `{"port":1081,"protocol":"http","users":["alice"]}`。用户名按字典序排列。端口及同一端口上的用户名均唯一，空数组表示移除全部监听。Agent 须额外声明 `xray_plan=v1` 才会领取包含此字段的任务，含 HTTP 专用端口的草稿还要求 `xray_http=v1`。节点 Token 心跳获取本节点草稿，Helper 只读预览并上报草稿摘要及候选引用。签发前 Master 校验该摘要仍对应保存的草稿，端口类型和用户名仍获节点目录许可。执行时 Helper 使用外层签名的草稿及本地目录重新渲染，独立核对精确配置引用。空数组时引用中的端口仍使用节点许可的非特权端口，实际监听以已应用授权数组为准。

新模板在同一字段中使用 `protocol: "vless"`、`"vmess"` 或 `"shadowsocks"`，领取时额外要求 `xray_protocols=v1`。心跳目录的 `port_protocols` 和 `protocol_users` 分别对应节点批准的端口类型和各协议的可授权用户名。签发及执行均要求两者与草稿一致。目录快照、授权和订阅只传输端口、类型和用户名，UUID 与密钥保存在节点本地。

Trojan 专用草稿项使用 `protocol: "trojan"`，并在 `users` 之前写入 `tls_cert_sha256`，值为已批准叶证书 DER 的小写 SHA-256。领取还要求 `xray_trojan_tls=v1`。节点心跳的 `trojan_trust` 仅包含公开证书和摘要。Master 签发前对照目录，Helper 渲染前按本地证书复验摘要。发布订阅时核对已应用草稿与已签名任务，只有获准 Trojan 用户的订阅包含该证书。证书私钥仅由节点保管，密码由部署方另行交付。

VLESS/REALITY 草稿项使用 `protocol: "vless-reality"`，并在 `users` 之前写入 `reality_public_key`，值为节点 X25519 公钥的无填充 Base64URL 编码。领取还要求 `xray_reality=v1`。Helper 从节点私钥派生公钥并复验签名草稿，订阅只向对应端口的获准用户返回已应用修订的公钥。UUID 和 Short ID 由节点管理员另行交付。

启用公网入口的 Trojan/TLS 或 VLESS/REALITY 草稿项在 `users` 之前附加 `public_endpoint`，对象字段为宿主公网 IPv4 `address` 和外部 TCP `port`。领取要求 `xray_public=v1`。Helper 复验目录中的映射、渲染后入站标记和固定 systemd 单元，已应用快照从已提交配置复原相同映射。受控草稿最大 1536 字节，订阅仅返回对应用户已签发且已应用的端点。

自定义网络草稿使用 `{"inbounds":[...],"network":{"outbounds":[...],"routes":[...]}}` 格式，最大 3072 字节。出站项绑定 `tag` 及 `destination`，目的含 `address` 和 `port`。路由条目按匹配顺序排列，各自绑定 `inbound_port` 和 `outbound_tag`。领取时须声明 `xray_routing=v1` 并具有草稿中入站的相应能力。心跳的 `catalog.routing_destinations` 携带节点批准的目的，`applied_network` 从已提交配置复原。旧入站草稿继续使用数组格式和原能力声明。

主控定义的草稿在 `network` 后附加 `panel.credentials` 数组，元素按入站端口顺序排列，每项是接收节点的 HPKE 密文。每入站允许一个客户端和至多一个 TCP 目标。心跳用 `panel_key` 通告节点的 X25519 公钥，主控首次保存时绑定该公钥。新草稿仍在 3072 字节限制内，并额外要求领取方声明 `xray_panel_inbounds=v1`。 [主控入站流程](./phase-4-xray-inbound.md#从主控添加入站)

主控 Trojan 另要求 `xray_panel_trojan=v1`。`panel.tls` 包含公开证书 `trust` 和密封的 Ed25519 私钥种子 `key`，其解密上下文绑定证书摘要。各 Trojan 入站引用同一摘要，可附带 `public_endpoint`。具备能力的节点心跳通告 `panel_trojan` 与 `panel_addresses`，应用后上报 `panel_tls`。主控只有在配置摘要、修订、端点和证书均与成功任务的签名草稿一致时才导出客户端元数据。 [主控公网接入](./phase-4-xray-inbound.md#从主控开通-trojantls-公网入口)

**取消对象**字段：`schema_version`、`node_id`、`task_id`、`sequence`、`issued_at`、`not_before`、`expires_at`、`signing_key_id`、`signature_algorithm`、`signature`，使用任务用途密钥和取消域。取消须目标精确匹配；可独立于顺序任务领取并持久化。取消先于开始则任务消费为 CANCELED；已开始只在操作定义的安全点停止并回滚，无法安全中止时继续完成既有已授权步骤或安全恢复，返回 `CANCEL_TOO_LATE`，不能虚报取消成功。取消与开始由本地同一事务/锁线性化。

**缺口跳过对象**字段：`schema_version`、`node_id`、`sequence`、`reason`、`issued_at`、`not_before`、`expires_at`、`signing_key_id`、`signature_algorithm`、`signature`；`reason` 仅 `VOID_UNISSUED`、`EXPIRED`、`CANCELED`。仅当前期望序号可消费，必须验签且有效；Master 必须证明该序号未签发或已有不可启动的终态，不能借 skip 替换已启动任务。为避免跳过未知已开始任务，节点存在该序号 RUNNING/未决记录时拒绝 skip 并进入对账。跳过是独立签名的空槽声明，不是新任务或任意跳号授权；其序号和不可变内容须持久化。签发 skip 后不得再签发该槽任务。

## 5. 序号、租约、ACK 与持久化恢复

- Master 在事务中为每节点保留下一个连续序号及不可变任务/skip 槽，审批消费、任务内容与签发意图持久化；签名服务崩溃后只能重试同一内容，禁止对同一槽签发不同内容。签发后持久化签名，重复投递字节一致；分配后未签发的空槽只能通过审计的 skip 关闭。持久化失败不得投递。
- Agent 持久化 `next_sequence`，仅接受该序号；更大序号触发缺口补取，不能静默前移。较小序号仅在与已存对象的 task ID、签名字节及规范化内容一致时返回已存结果，否则报冲突并停止高风险操作。对期望序号的认证有效任务先原子保存完整信封、状态和序号，再 ACK；任务未开始即过期时持久化 EXPIRED 并消费该槽，不执行；无效签名或错误目标不消费。未来 not_before 的任务等待，不得跳过。
- ACK 记录 `(node_id, task_id, status_version)`；状态版本正整数单调递增，重复上报内容一致则幂等确认，相同版本不同内容为冲突；Master 校验认证节点与任务归属，ACK 丢失可重发。结果、错误和审计不得包含密钥、完整配置或令牌。
- Master 租约仅是投递协调，不是执行授权：每次投递返回租约 ID 与截止时间，租约到期只允许重投同一不可变任务，不能创建不同任务替代或假设原任务未执行。Agent 不因租约过期重启已完成步骤；签名有效期及本地状态决定是否允许启动。任务最终状态未经确认时先对账，不重复签发同一业务副作用。
- 本地事务在副作用前持久化任务、步骤意图和足以判定结果的标识，提交并保证落盘；执行后持久化观察结果和状态。进程重启先对账外部实际状态，再确定已完成、可安全恢复或 `NEEDS_RECONCILIATION`；无法证明的副作用不得盲目重试。任务在有效期内开始后，过期或离线仅允许完成已经持久化且明确授权的正在进行步骤、检查及安全回滚；未开始的后续特权步骤不得启动，除非另有新的有效授权。取消同理不自动授权新动作。
- Helper 通过受限 Unix socket 和 `SO_PEERCRED` 校验 Agent 身份，独立验证原始任务、节点、类型、签名、有效期与实际参数逐字段一致；使用 root 私有账本持久化 `(node_id, task_id, step_id)`、签名授权摘要、步骤意图与结果，定义固定步骤及顺序后才开放相应操作。Agent 的 ACK 或租约不能替代 Helper 验签；Helper 崩溃后先对账，拒绝重复副作用。步骤授权、恢复和参数绑定未实现时相应操作禁用。
- 状态为 `QUEUED`、`LEASED`、`ACK_ACCEPTED`、`RUNNING`、`VERIFYING`、`SUCCEEDED`、`FAILED`、`ROLLING_BACK`、`ROLLED_BACK`、`EXPIRED`、`CANCELED` 或 `NEEDS_RECONCILIATION`。成功须有操作对应的健康验证；回滚失败明确告警，不伪装成功。任何状态转换与结果均须持久化，终态只返回原结果。

### 阶段 2 已接通的 V2 状态查询子集

状态查询使用 `schema_version: 2`、`operation: core.status`。V2 结构与 `not-applicable` / `observe` 语义见[状态任务协议草案](./phase-2-protocol-draft.md)。显式启用单签名清单的 Agent 通过 `install=xray-manifest-v1` 接收独立签发的 V1 `core.install`，共享同一节点序号。旧 TUF 节点使用 `install=xray-v1` 处理已投递任务。安装租约为 60 秒，同一节点凭据可为未过期的同一信封续租。租约到期只重投相同签名消息。Agent 账本先写入再处理；重复 ACK 可重放，执行中状态重启后进入 `NEEDS_RECONCILIATION`。[Xray 安装操作说明](./phase-3-operations.md#5-启用远程-xray-安装)

支持远程启停的 Agent 在轮询中声明 `xray_control=v1`。升级、降级、卸载使用 `xray_change=v1`。各操作共享租约、序号及 ACK 规则，Helper 校验已安装版本和架构。符合条件的签名安装、升级和降级任务可按目标摘要使用主控制品缓存。卸载只操作节点的受管版本。[远程启停](./phase-3-operations.md#6-远程启停) · [远程版本切换与卸载](./phase-3-operations.md#7-远程版本切换与卸载)

Helper 要求当前 Master 签发租约、提交完整原始签名消息并从 TLS 验证的 Master 获取当前时间和前序终态位置。检查点返回的前序序号只允许将已终结缺口写入 Helper 本地 ledger；未知缺口不跳过。状态读取仅执行固定 `systemctl show` 属性查询。Agent 过期收到的签名任务只持久化 `EXPIRED` 并 ACK，不执行 Helper。执行结果不确定时两端保持 reconciliation 栅栏，不能删除账本恢复。

V1 控制运行时当前允许：取消尚未过期、尚未开始的状态任务；以 `EXPIRED` skip 确认已过期任务；关闭未租出、未 ACK 的任务槽 `VOID_UNISSUED`；以及为可证明已过期的终态历史槽补取序号。Agent 每次轮询报告账本中的期望序号。活动、未过期、运行中或无法证明的缺口仍失败关闭；未实现独立 `CANCELED` skip 和原结果恢复。Master、Agent、Helper 通过 chrony 校验 Cloudflare `time.cloudflare.com` 的 NTS 状态、最近样本及误差界限，TLS Master 时间与节点时间偏差还需小于 30 秒。任务和审计数据分属两个 SQLite 文件；启动时检测两侧不一致并修复特定后置审计，配置独立检查点后会拒绝落后于远端记录的两库备份。两库仍各自提交。实现限制和验收状态见[阶段 2 进度](./phase-2-progress.md)。

### 5.1 阶段 0 冻结的并发与边界规则

- 每节点只有一个当前未终结槽，序号从 1 开始；同一节点任务串行。Master 用单写者 SQLite 事务为槽保存唯一不可变对象。分配与签名意图同一事务提交；不存在仅分配、未记录意图的序号。签名服务恢复只能重试相同内容。若已持久化但决定不发布，只能签发 `VOID_UNISSUED` skip 关闭该槽。
- Agent 原子保存当前信封后再 ACK，但只在终态（含未开始即过期、合法 skip、取消）时推进 `next_sequence`。`not_before` 尚未到的当前任务阻塞后续序号。过去序号只返回字节完全相同的持久化结果；相同序号不同对象隔离节点并告警。高序号请求只返回缺口，不修改状态。
- `expires_at - issued_at` 最长 10 分钟；任务到期前没有开始则持久化 `EXPIRED` 并消费槽。已开始任务不得因任务过期、离线或租约结束启动新特权步骤；已授权当前步骤可完成核验或安全回滚。不得延长签名时限。
- 投递租约固定 60 秒、每 15 秒允许续租；租约标识及截止时间仅协调投递，不能改变签名任务或执行权限。到期重发原始字节；最多 5 分钟指数退避后进入显式对账，不自动创建替代任务。
- 取消和开始通过 Agent 对同一节点账本的事务线性化。取消先提交且任务尚未进入 `RUNNING` 时状态成为 `CANCELED`；若 `RUNNING` 已先提交，返回 `CANCEL_TOO_LATE`，不新增取消步骤。先到的取消墓碑必须绑定 `(node_id, task_id, sequence)`；后到任务只在三者一致时消费为 `CANCELED`，冲突即隔离。
- skip 只接受当前期望序号且签名/用途/时限均有效。`VOID_UNISSUED` 由 Master 的未发布槽记录证明；`EXPIRED` 只能关闭已过期且未开始槽；`CANCELED` 必须对应已持久化的取消墓碑。Agent 有 `RUNNING`/未决记录时拒绝 skip 并对账。任何 skip 槽关闭后均不可再发布任务。
- ACK 的 `status_version` 从 1 单调递增，唯一键为 `(node_id, task_id, status_version)`。相同版本不同内容冲突；重复内容幂等。认证节点、任务归属和任务状态必须同时匹配。
- 每个操作定义固定有序步骤和参数摘要。未来阶段 2 的首个允许操作仅为 `core.status`，不得修改系统；其余 `config-policy.md` 中的 Helper 操作是未来白名单，尚未开放。Helper 接收原始任务和单个固定 `step_id`，逐字段校验本机观测参数，路径、URL、unit、脚本和 argv 永远不能来自请求。
- 重启时将 `ACCEPTED/WAITING` 重新做期限校验；`RUNNING/VERIFYING/ROLLING_BACK` 一律先检查实际系统状态，证据不足转 `NEEDS_RECONCILIATION` 并停止副作用。任务备份恢复须保留 Agent/Helper 的更高持久化高水位。怀疑回退时，先核对现存账本和节点状态，并核对已配置的独立检查点。无法确认状态时保持隔离。[单机备份恢复](./phase-2-operations.md#单机运行与备份恢复)

### 5.2 审批、密钥用途与发布边界

创建高危任务须由有目标范围的安全管理员发起，再由另一位安全管理员独立批准；发起者不得审批本人请求。批准绑定不可变任务规范化内容摘要、完整节点范围、Core/版本、固定步骤、有效期和一次消费。审批自发起起 30 分钟到期，任务签名最长 10 分钟。签发身份再次检查当前授权和审批状态，并原子消费；Web/任务状态字段本身不构成独立审批证明。阶段 1 邀请与节点禁用属于既有安全管理员 MFA 敏感操作，不构成任务审批。

任务签名密钥、制品发布密钥、HTTPS 服务端私钥和节点 Token 彼此分离。生产制品发布采用 [GitHub Releases 与单签名清单](./artifact-trust.md)，节点预置 Ed25519 发布公钥，通过本地带外配置更换。发布私钥由维护者离线保管。

## 6. 防回退与灾难恢复

Master 备份包括任务槽、签发意图和结果、每节点高水位、审批消费、节点及凭据撤销、配置 revision、签名密钥信任及审计。备份加密、访问受限并保留独立追加的安全检查点。恢复旧备份后先冻结节点接入和 Agent API、签发、轮换及高危任务。对照独立可信检查点和各节点/Helper 持久化账本，核对最高序号、未决任务、凭据撤销、信任版本及配置 revision，补齐经验证的不可变记录。任何无法证明新鲜或无法排除曾签发不同内容的槽均隔离人工处理。无法确认凭据撤销状态时，先作废恢复出的安装码和 Token，按原节点重新发放。完整对账并经授权安全管理员批准后恢复对应节点的签发。

Agent 或 Helper 状态丢失、回滚、损坏或身份重装时暂停所有新副作用；保留运行中的 LKG，报告 `NEEDS_RECONCILIATION`。操作员通过可信本地控制与 Master 独立记录确认身份、任务及实际系统状态，恢复可信账本并取得明确批准；不能证明连续性时保持隔离，须经本地人工重建并建立不可复用的新节点身份和独立序号空间，旧身份全部撤销。不得仅复制高水位、更换 Token 或忽略未知副作用。信任根损坏按第 2 节人工引导；未完成检查点独立性、操作步骤和故障演练前不宣称恢复可用。

## 7. 测试向量规范及验收

当前版本化共享向量位于 `internal/protocol/testdata/protocol-v1.json`：覆盖 task、config、cancel、skip 各一个签名正例，含乱序字段的等价输入和 9 个负例（含超出 10 分钟任务有效期）。正例提供完整 JSON、JCS 文本、签名字节、公开测试 seed、公钥、签名 hex/Base64；配置向量还提供精确原始字节、长度及 SHA-256。固定 seed 仅为公开测试材料，绝不能用于生产。

Go 测试通过 `internal/protocol` 校验 schema、拒绝负例并比对规范化签名字节；`scripts/verify-protocol-vectors.mjs` 使用 Node.js `crypto` 与独立实现的 ECMAScript JSON 规范化逻辑校验同一向量。当前已有两种语言/密码实现的互操作证据。向量覆盖本项目协议字段边界，不等于全部 RFC 8785 通用测试套件；阶段退出还要求项目内复核向量、拒绝行为与规范边界并记录结果。

每个正向量必须给出：向量 ID、对象类别和域前缀的精确 UTF-8 十六进制、完整输入 JSON、删除顶层签名后的 JCS 精确 UTF-8 文本及十六进制、完整待签名字节十六进制、32 字节公钥十六进制、测试私钥材料及其格式、64 字节签名十六进制与规范 Base64、预期验签结果；配置向量另附原始配置字节十六进制、长度和 SHA-256，以及与任务绑定的字段。分别覆盖 task、config、cancel、skip，包含字段乱序、转义和合法边界整数；重序和等价 JSON 表示应得到一致 JCS 和签名输入。非 ASCII 测例属于独立 JCS 规范化组件测试，当前协议字段不允许非 ASCII，不能将其作为协议对象正向量。

负向量至少覆盖：单字节修改签名或载荷、错误公钥/用途/域、错目标、重复键及转义后重复键、非法 UTF-8/孤立代理、额外字段、null、未知版本/算法、非规范 Base64、超长/越界/小数/指数、时间边界及过期、配置字节/长度/hash 不一致、revision 回退、同序号不同内容、skip 覆盖运行中任务。所有失败应注明预期拒绝层级且不得改变持久化状态或产生特权副作用；签名正确但语义越权配置仍须拒绝。

集成与故障注入应覆盖主控建节点后首次心跳、安装码并发兑换/过期/丢失响应、伪造服务器、跨节点 Token、凭据轮换和已建立连接撤销、时钟回拨、序号缺口补取、过期消费、取消与启动竞争、租约到期重复投递、ACK 丢失、每一步断电/磁盘满、Helper 重放、Master/节点旧备份恢复、LKG 恢复和不可判定状态隔离。结果须记录真实环境与证据，不以本设计文档代替执行结果。

## 8. 实现边界与发布阻断

1. 本文的一般序号、取消/skip、时限/租约、ACK 和恢复规则冻结为目标实现基线；阶段 2 当前落实只读状态任务与 pending cancel / expired skip 子集，项目内安全检查及负责人确认未记录，故阶段 0/2 均不能视为正式签核完成。
2. 当前 V2 状态签发服务、V1 控制签发、持久化任务存储、受限序号恢复、chrony NTS 检查和独立进程隔离已有代码；节点 Token 鉴权和可选的独立回滚检查点已接入主控。独立审批存储、独立 `CANCELED` skip 和完整带外恢复仍待实现。禁止将状态查询 signer 用于其他操作。
3. V1 任务 parser/向量与 V2 状态查询格式不同。[阶段 2 状态任务 V2 协议](./phase-2-protocol-draft.md)加入只读步骤字段与共享向量，用户于 2026-11-17 批准其作为阶段 2 开发基线；制品和架构的 `not-applicable` 仅适用于只读状态查询。批准不构成生产授权。
4. Helper 当前实现固定状态查询；Core 逐版本配置允许字段为空、默认拒绝。候选 Core 版本需按 [兼容矩阵](./core-compatibility.md) 实测后再拟定字段表。自更新、安装、配置、统计、真实恢复、通用 skip/序号恢复和制品信任运行时仍禁用。
5. 新 Xray 任务的 `artifact_id` 固定为 `xray-manifest-<架构>-<SHA256>`，并签入单签名清单的 `manifest_version`。旧 ID `xray-<架构>-<SHA256>` 仅绑定 TUF 的 `core-targets` 委派版本。[迁移步骤](./phase-3-release.md#3-从当前-tuf-实现迁移)
6. Agent 和 Helper 用固定的 `POST /api/v1/helper/artifacts/xray` 请求主控备用制品，发送当前安装签名信封 `task`、`lease_id` 和期望 `length`。Master 核对已投递任务、节点范围和当前租约，再按精确版本、架构、摘要及长度匹配缓存。客户端只使用已验签清单授权的字节。
