# 轻量化多 Core 主控面板 — Agent 技术设计文档 V1.0（安全修订稿）

> **文档类型**：技术设计 / 安全基线 / 开发实施指导  
> **版本**：V1.0 安全修订稿（尚非经过安全审计的实现）  
> **日期**：2026-11-16  
> **配套文档**：[《轻量化多 Core 主控面板——项目大纲与基础开发流程》](./project-overview-and-development-workflow.md)  
> **设计目标**：安全优先、Agent 默认空安装、主控按需管理 Core、可恢复、可审计、部署轻量。

---

## 0. 阅读说明与关键决定

本文的 Agent 借鉴 [miaomiaowuX / mmw-agent](https://github.com/iluobei/miaomiaowuX) 的主控—子节点管理方式，但**不复制其通信协议或安装策略**。下文出现的 JSON、Go 接口、目录和状态机均为本项目**拟定规范**，不是现有项目或上游 Core 已经实现的接口。

**已确定的 V1 约束：**

1. 安装 Agent 时**不安装、不打包、不启动** Xray、sing-box、Mieru/mita 等代理 Core。
2. 主控下发**结构化、带签名、限定目标的任务**，由 Agent 主动轮询领取。禁止远程 Shell、任意脚本和任意 URL 安装。
3. 支持 **Xray**、**sing-box**、**Mieru（服务端进程为 `mita`）**。一个节点可以安装三种 Core；V1 每种 Core 默认仅允许一个受控服务实例，避免多实例状态冲突。
4. Agent、特权 Helper 和各 Core 是**不同的安全边界**，分别使用最小运行权限。
5. 节点中断与主控通信后，已运行的 Core 可维持现状；**新的远程操作和新配置不能绕过验证**。
6. 部署目标先限定 **Linux + systemd、amd64/arm64**。主控和 Agent 均优先使用 Go；不用 Redis、消息队列和容器编排。
7. **安全门槛不可跳过**：身份认证、任务防重放、制品可信来源、权限隔离、审计、失败恢复必须先于公开发布。

**版本口径：**P0 表示开发先行、不可豁免的安全门槛；P1 表示完整 V1 发布前仍须交付的业务闭环。只完成 P0 可以作为内部安全底座验收，不能称作完整 V1。三种 Core 中无法可靠提供某项能力的锁定版本应在能力矩阵中显示 `UNSUPPORTED`，不应提供依赖该能力的精确额度功能。V1 发布条件以配套项目大纲第 12 章及本文第 14 章的合并清单为准。

**术语：**

| 术语 | 含义 |
|---|---|
| Master / Panel | 主控，维护节点、配置、用户、任务、凭据、审计 |
| Agent | 安装在节点上的低权限常驻程序，主动拉取、校验、调度任务 |
| Helper | 本地最小特权组件，仅做固定范围的文件、服务操作 |
| Core | 受管理的 Xray、sing-box、mita 进程与相关文件 |
| Artifact | 经可信发布清单绑定的 Core 安装制品 |
| Revision | 一份完整期望配置的不可变版本标识 |
| Task | 面向指定节点/指定 Core 的可验证、有生命周期的操作指令 |
| Last Known Good（LKG） | 最后一次被确认可用的二进制版本与配置 |

---

## 1. 需求范围

### 1.1 Agent 必须支持（P0）

- 空安装、首次注册、独立节点身份、证书轮换和节点撤销。
- 仅向可信 Master 发起 HTTPS 连接，正常管理接口使用 mTLS。
- 心跳、能力和运行状态上报；主控失联后的本地持续运行。
- 安全任务领取、签名验证、防重放、持久化状态、幂等与 ACK。
- Xray / sing-box / mita 三类 Core 的**按需安装、启动、停止、更新、降级、卸载**。
- 可信制品校验、固定目录安装、配置预检、失败回滚或安全停机。
- 可诊断的错误分类、脱敏日志、本地审计记录。
- Agent 自身升级也遵循可信发布机制，且不需要附带安装 Core。
- Helper 更新与 Agent 更新均须独立授权、健康确认、可回滚和本地恢复；未达到发布门槛前，不得开放远程更新入口。

### 1.2 后续阶段（P1）

- 三类 Core 各自的入站、用户及可用统计能力适配。
- 配置增量变化判断、版本化配置下发与安全切换。
- 流量上报的本地队列、重试、批次去重和额度状态同步。
- Core 异常重启、资源指标与可视化任务进度。

### 1.3 明确不做

- Agent 上开放公网 Web 管理面板或公网命令执行服务。
- 主控 SSH 登录节点、传递 root 密码或让 Agent 执行 `bash -c`。
- 由用户任意上传 ELF、修改下载 URL、指定可执行文件路径。
- 让 Core 进程访问 Agent 私钥、Helper Socket 或其他 Core 的敏感配置。
- 将三种 Core 的热重载、统计 API、用户管理方式假设为完全相同。

---

## 2. 系统结构与信任边界

```text
                           管理员浏览器
                                |
                          HTTPS + MFA
                                |
                  +-------------v--------------+
                  | Master / Panel              |
                  | 节点注册 / 任务 / 审计       |
                  | 配置 / 制品目录 / 流量       |
                  +-------------+--------------+
                                ^
                TLS / mTLS + 签名任务（Agent 主动 Pull）
                                |
+-------------------------------+----------------------------------+
| Node / Linux                                                       |
|                                                                     |
| +--------------------------+                                        |
| | lightpanel-agent          |  非 root，联网、校验、任务状态         |
| |   - Identity             |                                        |
| |   - Task Engine          |----本机 Unix Socket----+              |
| |   - Config Coordinator   |                       |              |
| |   - Heartbeat / Metrics  |                       v              |
| +--------------------------+           +------------------------+  |
|                                        | agent-helper           |  |
|                                        | 最小权限、固定操作      |  |
|                                        | 再验证授权与制品        |  |
|                                        +-----------+------------+  |
|                                                    |               |
|          +---------------------+-------------------+----+          |
|          |                     |                        |          |
|      Xray 服务            sing-box 服务             mita 服务       |
|      低权限用户           低权限用户               低权限用户      |
+---------------------------------------------------------------------+

注：代理客户端直接访问各 Core 的业务端口，不经过 Master。
```

### 2.1 组件职责与权限

| 组件 | 应当拥有 | 不应拥有 |
|---|---|---|
| Master | 节点元数据、任务授权、配置和用户管理 | 节点 root SSH 权限、远程通用命令入口 |
| Agent | 出站网络连接、本地状态库、节点私钥、受限 Unix Socket 访问 | root 权限、系统任意路径写权限 |
| Helper | 受控安装目录的文件管理、限定的 systemd 单元操作 | 任意 URL 下载、任意可执行路径、任意 Shell |
| Core | 配置读取、必要的业务端口和数据面资源 | Agent 凭据、Helper Socket、主控管理员权限 |

**特别提醒：**`mTLS` 保护的是通信和节点身份，不等于任务天然安全；**任务签名、制品签名、Helper 独立校验分别解决不同问题**，不能互相替代。

### 2.2 强制威胁假设

至少按以下攻击场景设计和验收：

- 攻击者截获/重放旧管理任务、伪造 Agent 或冒充 Master。
- 主控 API 或普通管理员账号被入侵，尝试越权安装恶意文件。
- 合法签名任务附带伪造/失效 `approval_id`，或签名配置启用了未授权监听、管理 API、文件读取或远程资源。
- Core 下载镜像被替换、制品/摘要同时被恶意修改。
- Agent 进程被利用，尝试通过 Helper 写任意路径或控制不属于本项目的服务。
- Agent 进程被利用，尝试把已签名任务中的摘要、Core、版本、revision 或服务动作替换为另一组实际执行参数。
- 不受信任的归档包包含 `../`、绝对路径、软硬链接或特殊设备文件。
- 更新途中断电、磁盘满、网络断开、服务健康检查失败。
- 旧任务覆盖新配置、上报重试造成流量重复累计。
- 某一 Core 被攻破后横向读取其他 Core 或 Agent 的凭据。

**无法保证的安全性质：**如果 Master 的合法高权限任务签名密钥及发布根信任均被攻破，节点仍面临系统性风险。应通过密钥隔离、分角色签名、高危操作审批、节点级范围限制和可恢复机制缩小影响，而不是承诺“绝对安全”。

---

## 3. Agent 启动与首次注册

### 3.1 本地安装内容

首次安装包仅包含：

1. `lightpanel-agent` 可执行文件；
2. 最小 `agent-helper` 可执行文件；
3. Agent 和 Helper 的固定 systemd 单元/Socket 配置；
4. 根信任材料（Master CA/固定 SPKI 或经验证的根公钥、制品根公钥等）与默认配置模板。

**不应包含任何 Core 二进制，也不应在安装脚本中自动下载 Core。** 安装引导脚本本身也需通过受信任渠道分发；不能把“curl 下载脚本直接以 root 执行”当作默认安全部署模式。

### 3.2 注册流程

```text
[运维人员在 Master 创建注册邀请]
          |
一次性邀请码（短有效期、限定节点组/用途）
          |
[节点本地安装 Agent，预置可信 Master 身份]
          |
Agent 本地生成不可导出的/受限访问的设备私钥 + CSR
          |
HTTPS 到可信 Master 的 /enroll（校验服务器证书）
          |
Master 校验邀请、CSR 的私钥持有证明、频率/来源限制
          |
人工批准或按策略批准；分配 node_id
          |
签发绑定 node_id 的客户端证书；吊销/过期信息入库
          |
Agent 持久化证书与身份；之后只使用 mTLS 管理接口
```

**注册注意事项：**

- 首次注册尚无客户端证书，`/enroll` 不能要求现有 mTLS 客户端身份，但**必须**验证 Master 的 TLS 身份；不允许以跳过证书校验代替引导。
- 一次性邀请码在主控端仅存储哈希，成功使用后原子标记消耗；设置短有效期、尝试次数限制、防枚举和审计。
- 在 Agent 上生成私钥，优先使用 OS 的密钥保护能力；绝不将私钥发送给 Master。
- `node_id` 由主控分配，注册后绑定到客户端证书的 SAN/受控身份字段；不允许 Agent 自行决定自己的身份。
- 二次注册、节点重装和证书丢失属于**恢复流程**，不能自动重用原邀请码。
- 证书撤销不应仅依赖 CRL/OCSP 的“在线可用性”：Master 应在应用层检查节点身份的当前状态、证书序列号与有效期。

### 3.3 证书轮换与失联

- Agent 在证书有效期到达预设阈值前发起轮换；使用当前有效证书申请新的证书，并证明新私钥持有权。
- 为避免服务中断，可允许短期双证书重叠，但应有精确的作废时间和审计记录。
- 若证书已过期、被吊销或 Master 身份不可信，**拒绝接受新任务/新配置**。已运行 Core 按离线策略继续使用 LKG。
- 系统时间明显失准时，进入受限状态并告警；不得为“修复”而关闭证书或任务时间校验。
- Master 地址变更或信任根轮换必须使用旧信任链授权的专用流程；彻底丢失信任时采用本地人工恢复。

---

## 4. 进程模型、权限与系统目录

### 4.1 运行账户

建议系统用户：

```text
lp-agent             Agent 主进程
lp-xray              Xray Core
lp-singbox           sing-box Core
lp-mita              mita Core
root                 受限 Helper（仅必要动作）
```

- Core 互相隔离，使用不同的低权限用户和文件访问策略。
- 需要绑定小于 1024 的端口时，优先由对应 systemd 单元**按需**授予 `CAP_NET_BIND_SERVICE`，而不是让整个 Core 以 root 运行。
- Helper 不接受 Agent 提供的 systemd 单元名称字符串，而是把受控 Core 类型映射到**内部固定允许列表**。
- Agent 升级、Helper 更新属于独立高风险操作，需要更严格的签名/审批；禁止 Helper 直接替换自己正在运行的程序而不经过安全切换。
- 即使普通 Agent 被攻破，只要 Helper 的授权账本和发布根仍可信，Helper 也只接受签名授权允许的精确操作。合法高权限签名者或发布根失陷时，这一隔离无法独自阻止恶意更新。

### 4.2 推荐目录与权限

```text
/usr/bin/lightpanel-agent                 root:root        0755
/usr/libexec/lightpanel/agent-helper      root:root        0755
/etc/lightpanel/agent/config.yaml        root:lp-agent    0640
/etc/lightpanel/cores/                   受限 Core 配置（按用户隔离）
/opt/lightpanel/cores/
  ├── xray/versions/<version>/           root:root 只读可执行制品
  ├── singbox/versions/<version>/        root:root 只读可执行制品
  └── mieru/versions/<version>/          root:root 只读可执行制品（mita）
/var/lib/lightpanel/agent/               lp-agent 私有状态、凭据和队列
/var/lib/lightpanel/helper/              root 私有授权序号和事务日志
/var/cache/lightpanel/downloads/         临时制品（大小/配额受限）
/run/lightpanel/helper.sock              Unix Socket，严格属主/权限
/var/log/lightpanel/                     脱敏审计与诊断（可用 journald）
```

**目录原则：**所有最终 Core 可执行文件必须由 root 拥有且对 Agent/Core 不可写；Core 不得读取 Agent 的证书、私钥和状态数据库。配置目录与运行日志目录也应分开。

### 4.3 Helper 接口安全（强制）

Helper 仅通过本机 Unix Domain Socket 对 Agent 暴露服务；需同时执行：

1. Socket 文件权限限制 + `SO_PEERCRED` 校验对端 UID/GID；
2. Helper **独立验证**任务签名、`node_id`、操作类型、参数范围与任务新鲜度；
3. Helper 独立持久化已授权操作的防重放记录，避免 Agent 被攻破时复用旧高权限请求；
4. 对 Core、安装路径、systemd 单元、制品摘要使用严格的预定义映射；
5. 仅允许以下原子级操作：安装已验证制品、切换允许的版本、设置固定权限、控制固定服务、写入经校验的配置/回滚文件；
6. **拒绝**执行任意命令、创建任意系统用户、写任意路径、编辑任意 systemd 单元或通过任意 URL 下载。

7. 将 `SignedTask` 中的 `(node_id, task_id, action, core, artifact_id/manifest_version 或 revision/hash, 操作条件)` 与 Helper 请求的实际参数逐字段比对；禁止请求中新增未签名的路径、服务名、参数或内容。对于可拆分的多个特权步骤，应预先定义签名允许的步骤、顺序和重试语义。
8. `SO_PEERCRED` 只能证明本机调用进程身份，不能代替签名和策略。Helper 在 root 私有账本中记录已消耗的特权步骤、结果与恢复标记；重启后先对账，拒绝重复副作用。

示意 API（内部，不暴露网络）：

```go
// 只描述调用意图，不允许命令字符串、绝对安装路径或自定义 argv。
type HelperOperation struct {
    TaskID       string
    NodeID       string
    Action       string // INSTALL_CORE | ACTIVATE_CORE | APPLY_CONFIG | SERVICE_CONTROL
    Core         string // XRAY | SING_BOX | MITA
    ArtifactID   string // 必须能在可信清单中查到
    Revision     string // 配置内容摘要/版本
    SignedTask   []byte // Helper 独立复验原始可信授权
}
```

Helper 的配置写入只接受已验签 revision 的精确内容摘要，并实施固定目录和权限策略；配置语义另由主控与 Agent 的 Core 策略检查。可执行制品校验或配置预检若需运行候选二进制，应在低权限、隔离网络/文件访问的环境执行，不能让未激活的候选制品获得 Helper 的 root 权限。

> 可选的 Linux 细化：涉及路径解析时尽量使用目录文件描述符及 `openat2` 的防逃逸解析约束，并拒绝软链接、硬链接和特殊文件。**不能只靠 `filepath.Clean()` 防御路径穿越和 TOCTOU。**

### 4.4 systemd 沙箱基线

Agent/Core 分别设置合适的 `User=`、`NoNewPrivileges=yes`、`ProtectSystem=strict`、`ProtectHome=yes`、`PrivateTmp=yes`、`RestrictSUIDSGID=yes`、有限的 `ReadWritePaths=` / `StateDirectory=` / `RuntimeDirectory=`，并按实际网络和文件访问需求验证 `CapabilityBoundingSet=`。

不要直接复制一套过严的沙箱参数而不测试：不同 Core 的 DNS、证书、日志、网络套接字和 `mita` 内部配置目录可能受影响。以各 Core 的实际运行需求建立最小化单元模板，并使用 `systemd-analyze security` 辅助检查，而不是把评分作为唯一安全证明。

---

## 5. 主控—Agent 通信协议

### 5.1 连接模型

**只使用 HTTPS Pull（V1）**：Agent 周期性请求 Master，不在节点上监听公网管理端口。HTTP 请求全部限制超时、响应大小、并发和重试退避，拒绝不可验证的跳转。

| API | 作用 | 主要认证 |
|---|---|---|
| `POST /api/v1/agent/enroll` | 首次注册/证书申请 | Master TLS + 一次性邀请 + CSR 证明 |
| `POST /api/v1/agent/heartbeat` | 心跳、版本、节点健康摘要 | mTLS + 节点状态校验 |
| `GET /api/v1/agent/tasks` | 顺序领取任务 | mTLS，响应内任务另行验签 |
| `POST /api/v1/agent/tasks/{id}/ack` | 状态、结果、错误码 | mTLS + 任务归属校验 |
| `GET /api/v1/agent/config?revision=...` | 获取签名/哈希绑定配置 | mTLS + revision + 签名校验 |
| `POST /api/v1/agent/traffic` | 幂等流量批次提交（P1） | mTLS + 批次 ID / 序号 |
| `POST /api/v1/agent/health` | Core 与资源指标（P1） | mTLS |

**建议默认周期**：心跳 15 秒、任务轮询 15 秒、流量补报 30 秒、主控将 60 秒无心跳判定为“离线”。增加随机抖动和指数退避，避免大量 Agent 同时重连导致主控雪崩。

### 5.2 任务信封（示例 schema）

```json
{
  "schema_version": 1,
  "task_id": "01JEXAMPLEULID000000000000",
  "node_id": "node-001",
  "sequence": 105,
  "operation": "core.install",
  "issued_at": "2026-11-16T08:00:00Z",
  "not_before": "2026-11-16T08:00:00Z",
  "expires_at": "2026-11-16T08:10:00Z",
  "payload": {
    "core": "xray",
    "version": "<approved-semver>",
    "artifact_id": "sha256:<approved-content-digest>",
    "manifest_version": 17
  },
  "approval_id": "approval-123",
  "signing_key_id": "task-key-2026-01",
  "signature_algorithm": "Ed25519",
  "signature": "<base64-signature>"
}
```

- 签名必须覆盖**除签名本身外**的规范化字段以及 `signing_key_id`，并使用**域分离前缀**避免不同业务消息跨协议复用。
- V1 选定 **Ed25519 + RFC 8785 JSON Canonicalization Scheme（JCS）** 或明确规定的规范化 CBOR；全项目只能选一种，避免“双方解析结果不同”造成验签绕过。
- 消息解析必须拒绝重复 JSON key、未知危险字段、非法数值/日期、超大对象和不支持的 `schema_version`。
- `payload` 不包含下载 URL、Shell、绝对安装路径、systemd unit 名称或任意命令参数。
- 安装/降级的版本与摘要必须同时匹配 Agent 本地信任的发布清单。
- `sequence` 在**每个节点**上单调递增；`task_id` 全局唯一；Agent 和 Helper 各自将已处理序号与任务结果落盘。过期/取消的任务应按规则标记消费，不得因序号断档无止境阻塞后续任务。
- 主控必须为每节点持久化分配序号，并定义断档补取/显式跳过协议；Agent 不因收到一个高序号就静默丢弃中间任务。取消须有独立签名、目标与序号约束。任务在**开始前**过期不得启动；在有效期内已开始的任务可按持久化事务继续完成恢复，但不能借此启动未授权的新步骤。
- 时间校验允许小范围时钟漂移（策略化），不得无限放宽。可疑时间回退应暂停高风险操作并告警。
- 主控对某个任务的重复投递不应导致重复安装/删除，返回原任务最终结果。

**关于签名密钥：**日常 task 签名私钥应与制品发布根密钥分离，优先通过独立签名服务/KMS 或至少隔离部署。**根发布私钥不放在普通主控 Web 进程里。** 对更新 Agent/Helper、信任根变更等操作使用更高权限和独立批准机制。

**签发前置条件：**Web API 逐次检查操作者的操作权限和节点/用户/配置对象权限；审批记录绑定规范化任务参数摘要、目标、审批人、有效期、复验结果和使用次数。签发服务在签名时重新核对审批状态并原子消费授权；只在任务信封中填写 `approval_id` 不足以证明审批。高危操作要求与日常管理员操作分离的批准权限；信任根变更至少两名不同授权人。Agent 负责验证签名及节点侧策略，不能以未签名的审批 API 响应替代授权。

### 5.3 允许的任务类型

| 任务 | 作用 | 权限级别 | 默认行为 |
|---|---|---|---|
| `core.install` | 安装特定 Core 固定版本 | 高 | 验签、验制品、健康检查 |
| `core.upgrade` | 更新已安装 Core | 高 | 保留 LKG，失败回滚 |
| `core.downgrade` | 显式安装历史版本 | 高 | 需要额外审批和回滚授权 |
| `core.uninstall` | 卸载指定 Core | 高 | 二次确认、默认保留审计数据 |
| `core.start` / `core.stop` / `core.restart` | 控制固定服务 | 中 | 仅作用于任务目标 Core |
| `config.apply` | 应用指定 revision | 高 | 预检、受控切换、失败恢复 |
| `agent.rotate_credentials` | 轮换节点凭据 | 高 | 双证书短暂重叠、可撤销 |
| `agent.update` | 更新 Agent/Helper | 极高 | 独立发布签名及恢复流程 |

不增加 `exec`、`script.run`、`systemd.manage_any` 等通用命令任务。

### 5.4 任务状态机与恢复规则

```text
QUEUED
  |
  v
LEASED ---> ACK_ACCEPTED ---> RUNNING ---> VERIFYING ---> SUCCEEDED
  |                           |                |
  |                           |                +------> FAILED
  |                           +------> ROLLING_BACK ---> ROLLED_BACK
  |
  +------> EXPIRED / CANCELED（尚未发生不可逆副作用时）

Agent 重启后：依据本地 WAL/状态库恢复、对账，不能盲目重放副作用。
```

**关键规则：**

- Agent 一次仅串行执行一个**改变同一 Core 状态**的任务。不同 Core 可扩展并发，但 Core 安装、Helper 权限操作仍需有全局锁或资源协调。
- 任务持久化事务先于执行；每一步写入“意图 + 阶段 + 结果”，并使用 `fsync`/事务提交保证断电后可恢复。
- 主控领取租约（lease）过期不等于原任务没有执行；不能因收不到 ACK 就创建新的不同任务重复操作。
- 主控数据库恢复时必须保留节点序号、撤销记录和任务最终状态；恢复到旧备份后若无法证明这些状态新鲜，应暂停签发和高危执行，走受控恢复流程。
- `SUCCEEDED` 意味着操作已完成并通过已定义的验证，**不能只以命令退出码 0 判定**。
- 状态和结果上报可重试，Master 按 `(node_id, task_id, status_version)` 去重。
- Agent 发现服务实际状态和本地记录不一致时，标记 `NEEDS_RECONCILIATION`，停止高风险写操作并上报人工/受控修复需求。

### 5.5 错误码约定

```text
AUTH_INVALID_CERT
AUTH_NODE_REVOKED
TASK_BAD_SIGNATURE
TASK_EXPIRED
TASK_REPLAYED
TASK_UNSUPPORTED_OPERATION
ARTIFACT_NOT_TRUSTED
ARTIFACT_DIGEST_MISMATCH
ARTIFACT_ARCH_MISMATCH
ARTIFACT_EXTRACT_BLOCKED
HELPER_DENIED
CONFIG_VALIDATION_FAILED
PORT_CONFLICT
CORE_START_TIMEOUT
CORE_HEALTH_FAILED
ROLLBACK_FAILED
DISK_SPACE_INSUFFICIENT
STATE_RECONCILIATION_REQUIRED
```

外部错误不包含完整配置、用户密钥或敏感本地路径；详细诊断仅记录脱敏事件与最小必要上下文。

---

## 6. 可信制品、安装与更新

### 6.1 信任链设计

**必须明确区分三种签名：**

1. **任务签名**：证明指定 Master 的授权者允许此节点在此时执行指定动作。
2. **发布清单签名**：证明 Core 类型、版本、架构、下载位置及 SHA-256 摘要来自受信任的发布流程。
3. **上游制品签名（可用时）**：证明取得的上游发布件具备官方可验证来源。没有官方签名时，应在独立的审核/构建流程中形成内部签名清单。

不能因为从 HTTPS 下载成功、或下载的文件与**同一未经信任来源提供**的 SHA-256 一致，就认为安装包可信。

建议发布系统逐步采用 [The Update Framework (TUF)](https://theupdateframework.github.io/specification/latest/) 思路（根信任、目标文件、版本/时间戳、防回滚/冻结）。V1 即使暂时实现简化签名清单，也应包含签名、公钥轮换、版本递增和过期控制，避免以后推翻制品模型。

**发布前必须二选一并冻结协议：**采用经过验证的 TUF 客户端/仓库实现；或记录简化方案相对 TUF 缺失的保证，并明确多签阈值、清单单调版本、过期/离线时禁止新安装、根密钥轮换、旧版本降级的独立授权及从旧备份恢复的处理。过期清单不能因 Master 暂时离线而被默许为新安装依据。发布根私钥独立于在线任务签发服务保管。

### 6.2 制品清单最小字段

```json
{
  "manifest_version": 17,
  "expires_at": "2026-12-01T00:00:00Z",
  "artifacts": [
    {
      "id": "artifact-xray-linux-amd64-example",
      "core": "xray",
      "version": "<approved-semver>",
      "os": "linux",
      "arch": "amd64",
      "sha256": "<64-hex-digest>",
      "size": 12345678,
      "source_id": "trusted-mirror-1",
      "archive_format": "zip"
    }
  ],
  "signatures": ["<signed-metadata-signatures>"]
}
```

示例字段并非最终的 TUF 规范实现，正式实现必须选定明确的签名封装格式，**不能将 `signatures` 当作待签名原文的一部分形成循环定义**。发布清单应固定 Core 类型与平台元数据、构建来源及审核记录。

### 6.3 Core 安装事务

```text
1. validate_authorization    验证任务、签名、策略、序号、Core 类型
2. resolve_manifest          查可信清单，锁定版本/架构/摘要
3. preflight                 检查 OS/架构、磁盘空间、目录权限、端口
4. download_to_staging       固定可信源下载，限流、限大小、超时
5. verify_artifact           清单签名、有效期、摘要、大小、架构
6. safe_unpack              拒绝越界路径、链接、设备文件、非法权限
7. stage_version            写入仅 root 可修改的独立版本目录
8. validate_binary/config   固定允许的二进制自检/配置检查
9. activate                 更新受控版本指针，管理固定 systemd 服务
10. healthcheck             进程/监听/协议层必要健康检查
11. commit                  记录当前版本和 LKG，持久化成功
12. rollback_on_error       恢复原版本与配置并复核健康
```

**安装额外防护：**

- 拒绝下载地址跳转到不在白名单的主机；禁用 `file://`、云元数据地址及内网非预期地址（防 SSRF）。Agent 不从任务载荷直接读取 URL。
- 限制下载字节、压缩后字节、文件数量、路径深度、解包时间，防止归档炸弹。
- 归档解包需拒绝绝对路径、`..`、符号链接逃逸、硬链接、SUID/SGID、特殊文件，阻断 TOCTOU。
- 不在可执行目标目录内直接下载或解压；验证成功后由 Helper 原子移动到版本目录。
- 对 Agent 可写的临时目录绝不直接赋予 root 执行权限；Helper 应通过受信任文件描述符/只读方式重新验证最终制品。
- 明确禁止从非受信任 Core 包执行安装脚本、post-install hook 或其他自定义程序。

### 6.4 更新与回滚

- 同一 Core 用不可变版本目录保存多个版本；`current` 指针由 Helper 受控切换。
- **二进制指针切换可原子化，但“服务正常运行”并非原子操作**；必须保留服务状态、配置兼容性、启动结果的事务日志。
- 如果新版本健康检查失败，恢复旧二进制、旧配置、旧服务状态并检查恢复成功；如果无法恢复，标记 `ROLLBACK_FAILED`，停止自动重试并告警。
- 降级只有在专门的已批准任务下允许；普通更新不能绕过清单版本防回滚策略。
- 自动清理旧版本应保留至少一个 LKG，且不能删除当前正在运行的版本。
- 卸载默认停止 Core、移除受控二进制和服务链接、保留审计与必要配置备份；敏感数据是否彻底删除由显式策略控制。

**Agent/Helper 自身更新事务（V1 发布门槛）：**使用独立发布元数据和更高权限的更新任务；在 root 拥有的不可变版本目录内暂存并复验新程序、架构和依赖；切换后由旧版本可控的监督路径设置启动确认期限；新版本完成身份、状态库和 Helper 握手检查后才提交。超时或异常退出恢复旧程序、旧协议兼容的状态和服务；Helper 不直接覆盖自己的运行文件。必须用断电、磁盘满、签名错误、协议不兼容及更新后无法启动的实机演练证明恢复，另提供无需 Master 的本地人工修复步骤。

---

## 7. 三种 Core 的适配设计

### 7.1 统一抽象与能力集

**V1 分层：**

- `CoreManager`：共同的安装、升级、卸载、版本、事务和 Helper 协调。
- `CoreAdapter`：不同 Core 的配置、进程健康和统计适配。
- `Capabilities`：告诉主控哪些配置/统计功能确实可用。

```go
type CoreType string
const (
    CoreXray    CoreType = "xray"
    CoreSingBox CoreType = "sing-box"
    CoreMita    CoreType = "mita"
)

type Capabilities struct {
    SupportsConfigCheck  bool
    SupportsHotReload    bool
    SupportsUserStats    bool
    SupportsUserQuota    bool
    SupportsGracefulStop bool
}

type CoreAdapter interface {
    Type() CoreType
    Capabilities(ctx context.Context, version string) (Capabilities, error)
    ValidateConfig(ctx context.Context, path string) error
    ApplyConfig(ctx context.Context, revision string) error
    Probe(ctx context.Context) (CoreHealth, error)
    CollectTraffic(ctx context.Context) ([]TrafficCounter, error)
}
```

`CollectTraffic` 可以返回“功能不支持”的类型化结果，不能返回空数组却在 UI 显示“统计为零”。Core 适配必须跟踪**确切版本和构建选项**，不假定跨版本永久兼容。

配置适配采用明确的策略校验：只允许已测试的监听地址/端口、管理 API 绑定方式、文件/日志路径、外部规则资源与出站行为；发现未识别字段或无法安全解释的版本差异时拒绝应用，并标记能力未知。签名和 Core 自身的语法检查都不能代替策略检查。

### 7.2 Xray

- 可使用官方命令所提供的 `xray run -test -c <config>` 校验配置（实际执行时使用固定二进制与固定参数向量，不经过 Shell）。
- Core 的进程状态由 systemd 查询；启用统计接口时，应将本地统计 API 限制在本机可访问范围并通过低权限/授权校验控制访问。
- 配置改变优先使用已验证的对应版本机制；若不能安全热更新则受控重启。
- 更新时需考虑 Xray 配置版本兼容性与数据文件依赖，不能只替换可执行文件。

### 7.3 sing-box

- 官方文档提供 `sing-box check` 用于配置检查，可按受支持版本与配置路径执行校验。
- sing-box 版本升级可能涉及已弃用字段、规则集、实验性 API 变化，必须用**目标新版本**对候选配置预检。
- 用户级流量统计能力依赖版本、构建选项及配置。V1 没有经过验证的能力时标记 `UNSUPPORTED`，不伪造用户统计。
- 将本地 API、日志、缓存或可写目录限制在该 Core 独立的沙箱内。

### 7.4 Mieru / mita

- 产品名称为 **Mieru**，实际服务端是 **`mita`**，不能将客户端 `mieru` 误当作服务端 Core。
- 官方文档提供 `mita apply config`（合并现有配置）、`mita replace config`（替换完整配置）、`mita start/stop/status`；用户/流量相关操作包括 `mita get users`、`mita get quotas`。
- **对受主控管理的完整配置建议优先采用可控的 replace 语义**；使用 apply 合并语义可能留下旧字段，破坏“主控期望状态 = 本地实际状态”的一致性。
- 配置由 `mita` 内部持久化时，需要在应用前记录其真实配置快照及可恢复位置；**仅切换外部 JSON 文件不保证回滚已生效的内部状态**。
- 官方资料说明修改大部分配置需要停启服务；仅变更用户或日志级别时可考虑支持的 `reload`，必须以实际版本测试为准。
- `mita` 的配额和用户统计具有自身的时间窗口、持久化与计数语义，转换为主控统一用量时需定义口径、采样基线和重置检测。

### 7.5 三种 Core 的 V1 能力矩阵

| 能力 | Xray | sing-box | Mieru/mita |
|---|---|---|---|
| Core 按需安装/更新 | P0 | P0 | P0 |
| 进程启停与监控 | P0 | P0 | P0 |
| 配置检查/安全应用 | P1 | P1 | P1（需验证内部状态） |
| 用户/入站管理 | P1 | P1 | P1（按独立用户模型） |
| 用户流量统计 | 依赖可用统计接口 | 依赖版本与构建 | 依赖 mita 统计语义 |
| 无损热重载 | 不预设 | 不预设 | 仅符合支持条件时 |
| 多实例/同类型并存 | V1 不做 | V1 不做 | V1 不做 |

---

## 8. 配置同步、状态对账与回滚

### 8.1 期望状态与实际状态

主控管理的是 **Desired State**，Agent 上报的是 **Observed State**。配置标识建议如下：

```json
{
  "node_id": "node-001",
  "core": "xray",
  "revision": 42,
  "content_sha256": "<sha256-of-exact-config-bytes>",
  "generated_at": "2026-11-16T08:00:00Z",
  "schema_version": 1,
  "signing_key_id": "config-key-2026-01",
  "signature": "<signed-config-envelope>"
}
```

设计规范：

- 每个 `(node_id, core)` 拥有**单调递增**的 revision；配置 bytes 必须与签名/摘要严格绑定。
- Agent 先验证签名、目标身份、版本、最大大小、Core 类型；再下载候选配置；然后使用目标 Core 执行预检。
- 在主控生成及 Agent 应用前，均按锁定 Core 版本和节点安全策略校验配置语义。禁止通过签名配置访问 Agent/Helper 凭据或暴露本地管理接口；外部资源只允许固定可信来源及摘要绑定，无法做到时禁用此能力。
- 需要 Core 切换的配置先保留 LKG、记录事务、按 Core 特性应用；失败恢复旧配置和旧进程状态。
- 旧 revision 不得覆盖新的已确认 revision；手动回滚需产生**新的 revision**，内容可以等于历史版本，以保持单调性。
- Agent 不能依据本地随意修改的临时文件直接更改正在运行的 Core；所有实际应用都要可追溯到签名 revision 或受控本地恢复记录。

### 8.2 启动对账

Agent 每次启动需检查：

1. 已记录的 Core 安装清单与磁盘文件是否一致；
2. `current` 指针、LKG 与 systemd 当前实际状态是否一致；
3. 上一个任务是否处于“已开始但未提交”的状态；
4. Core 配置内容哈希是否匹配已记录 revision；
5. 上报队列是否有待确认批次。

有冲突时优先保留正在工作的 LKG 或安全停机，记录详细错误，不自动执行不可追溯的“修复脚本”。

### 8.3 离线策略

| 情况 | Agent 应对 |
|---|---|
| Master 暂时不可达 | 已运行 Core 保持原状；任务延后；周期性退避重连 |
| mTLS 失效/节点撤销 | 不接受新任务；维持或停止 Core 由预先配置的安全策略决定；记录告警 |
| 正在下载时断线 | 可保留已校验的分片，但不得在缺失授权/清单新鲜度时激活 |
| 已通过校验且正在安装时断线 | 依据本地已授权任务和事务日志完成安全恢复；不得接收新的未验证指令 |
| 配置获取不完整或摘要不匹配 | 不应用，保持 LKG |

> 不建议默认“Master 失联立即停止代理服务”，否则主控网络故障会放大为全部节点业务中断。但对已经明确撤销、过期或高风险节点，应提供可配置且可审计的停机策略。

---

## 9. 流量统计与本地可靠队列（P1）

### 9.1 统一计数结构

```go
type TrafficCounter struct {
    Core          CoreType
    LocalUserKey  string
    UplinkBytes   uint64
    DownlinkBytes uint64
    CounterEpoch  string // 重启/重置或统计窗口发生变化时改变
    ObservedAt    time.Time
}
```

- 明确各 Core 的方向定义（上/下行）和统计粒度。`LocalUserKey` 必须映射主控稳定的用户身份，避免不同 Core 用户名重名。
- 若上游提供的是累计计数：Agent 保存最近已确认的基线，生成**非负增量**；计数器归零、回绕、进程重启或统计窗口切换必须识别新的 `CounterEpoch`。
- 若提供的是日/30 日滚动窗口等非单调统计，**不能直接相减当作可靠增量**；应适配特定模型或暂时禁用精确计费。
- 采集、生成批次、入本地 WAL/SQLite 与标记已上报之间必须有明确事务边界。

### 9.2 上报与去重

```json
{
  "node_id": "node-001",
  "batch_id": "node-001/0000000421",
  "sequence": 421,
  "created_at": "2026-11-16T08:30:00Z",
  "records": [
    {
      "core": "xray",
      "user_id": "user-001",
      "counter_epoch": "epoch-a",
      "uplink_delta": 1024,
      "downlink_delta": 2048
    }
  ]
}
```

- Agent **先持久化后发送**，收到主控成功确认后再删除或归档；断网时按受限容量缓存。
- 主控以 `(node_id, batch_id)` 唯一约束/事务去重，重复上报返回同一确认结果，不再累计。
- 丢失本地数据库、Core 统计重置或来源能力不足时，标记统计不完整，绝不“猜测填补”。
- 多节点用户总额度为近实时汇总；离线允许使用多少额度必须由主控另行定义业务策略。

---

## 10. Agent 内部模块与建议代码目录

```text
lightpanel/
├── cmd/
│   ├── panel/
│   ├── agent/
│   └── agent-helper/
├── internal/
│   ├── agent/
│   │   ├── bootstrap/          # 首次注册、Master 身份校验
│   │   ├── identity/           # 节点证书、密钥、轮换
│   │   ├── transport/          # HTTPS/mTLS、限流、重试
│   │   ├── heartbeat/          # 健康及版本上报
│   │   ├── tasks/              # 验签、调度、状态机、幂等
│   │   ├── coremanager/        # 制品事务、版本与 LKG
│   │   ├── configsync/         # revision 校验及应用
│   │   ├── adapters/
│   │   │   ├── xray/
│   │   │   ├── singbox/
│   │   │   └── mieru/
│   │   ├── traffic/            # 计数和待确认上报
│   │   ├── reconcile/          # 启动对账、异常恢复
│   │   └── storage/            # SQLite/WAL 与迁移
│   ├── helper/
│   │   ├── policy/             # 自主验签/授权/防重放
│   │   ├── fsops/              # 固定范围安全文件操作
│   │   ├── service/            # 固定 systemd 服务控制
│   │   └── transaction/        # 安装事务/回滚日志
│   └── security/               # JCS、Ed25519、可信根、清单
├── pkg/protocol/               # Master/Agent 共用模型
├── migrations/                 # 主控/Agent 状态库迁移
├── packaging/systemd/         # 单元模板和 Socket
├── scripts/                   # 受控发布/测试脚本
├── tests/                     # 集成、故障与安全测试
└── docs/
    ├── agent-design.md        # 本文
    ├── agent-protocol.md      # 最终线协议规范（待定稿）
    ├── threat-model.md        # 威胁模型（待审计）
    └── core-compatibility.md  # 具体支持版本矩阵
```

**建议本地状态表：**

```text
agent_identity             节点 ID、凭据版本、信任根版本
processed_tasks            任务 ID、序号、状态、结果哈希
helper_authorizations      特权操作授权及防重放记录（root 私有）
core_installations         Core 类型、版本、制品、运行状态
config_revisions           当前 revision、LKG、哈希
operations_journal         安装/切换事务步骤与恢复标记
traffic_baselines          各统计源基线、epoch
traffic_outbox             待 ACK 的增量批次
security_events           最小必要安全事件
```

普通 Agent 状态库与 root 私有 Helper 防重放账本分开，不能由普通 Agent 修改 Helper 已批准的历史记录。

---

## 11. 安全检查与测试矩阵

### 11.1 身份/通信测试

| 编号 | 用例 | 期望结果 |
|---|---|---|
| SEC-ID-01 | 未注册 Agent 请求任务 | 拒绝 |
| SEC-ID-02 | 伪造 Master 证书 / MITM | Agent 拒绝连接 |
| SEC-ID-03 | 重复使用一次性邀请码 | 仅首次有效，后续拒绝 |
| SEC-ID-04 | 撤销节点证书仍请求任务 | Master 拒绝 |
| SEC-ID-05 | 证书轮换后旧证书超出重叠期 | 拒绝 |
| SEC-ID-06 | 时间回拨或过期任务 | 拒绝高危任务并告警 |

### 11.2 任务与 Helper 测试

| 编号 | 用例 | 期望结果 |
|---|---|---|
| SEC-TASK-01 | 修改已签名任务 payload 任意字段 | 验签失败 |
| SEC-TASK-02 | 任务目标 node_id 不匹配 | 拒绝 |
| SEC-TASK-03 | 重放历史 `core.uninstall` | 无重复副作用，记录安全事件 |
| SEC-TASK-04 | 使用未定义任务 `script.run` | 拒绝 |
| SEC-TASK-05 | Agent 伪造 `unit=sshd.service` | Helper 拒绝 |
| SEC-TASK-06 | 其他系统用户调用 Helper Socket | 拒绝 |
| SEC-TASK-07 | Agent 进程被模拟入侵，尝试越权文件写入 | Helper 拒绝，系统目录无变化 |
| SEC-TASK-08 | Agent 重启后重领正在执行的安装任务 | 对账或恢复，不重复危险操作 |
| SEC-TASK-09 | 伪造/重复审批 ID，或审批后修改目标、版本、摘要 | 主控拒绝签发；Helper 拒绝不匹配的实际参数 |
| SEC-TASK-10 | 任务序号缺口、已开始任务过期、取消与租约同时发生 | 按协议恢复，不跳过授权或重复副作用 |

### 11.3 制品/配置/恢复测试

| 编号 | 用例 | 期望结果 |
|---|---|---|
| SEC-ART-01 | 修改压缩包但保留原摘要 | 校验失败 |
| SEC-ART-02 | 伪造 manifest / 旧过期清单 | 验签或新鲜度检查失败 |
| SEC-ART-03 | 归档路径含 `../`、绝对路径或逃逸链接 | 拒绝解包 |
| SEC-ART-04 | 压缩炸弹、超大下载和大量小文件 | 在限额处终止 |
| SEC-ART-05 | 下载中断、断电、磁盘写满 | 不破坏旧 LKG |
| SEC-ART-06 | 更新新 Core 后启动失败 | 恢复旧版本并核实健康 |
| SEC-CFG-01 | 配置哈希不匹配 / revision 回退 | 拒绝 |
| SEC-CFG-02 | 端口冲突或校验失败 | 不应用配置 |
| SEC-CFG-03 | mita 修改了内部持久化配置后失败 | 依设计快照恢复，并标记可验证结果 |
| SEC-CFG-04 | 已签名配置启用对外管理 API、越界文件路径或未经批准的远程资源 | 主控或 Agent 拒绝应用，LKG 保持有效 |
| SEC-UPD-01 | Agent/Helper 更新中断、启动超时或协议不兼容 | 自动恢复旧版本；本地人工修复可执行 |
| SEC-TRAFFIC-01 | 重复发送同一批次 | 主控只统计一次 |
| SEC-TRAFFIC-02 | 断网后重连补报 | 不丢已入库且仍有效的批次 |

### 11.4 额外质量门槛

- 对任务解析、JCS/签名验证、解包处理、Helper 请求解析执行 fuzz 测试。
- `go test -race`、静态分析、依赖漏洞扫描、生成 SBOM、发布制品签名与可追溯构建。
- 使用非 root、无 Core 的干净 Linux VM 做端到端验收；覆盖 amd64/arm64。
- 提供主控离线 24 小时、Agent 异常重启、失联恢复、证书轮换失败、系统重启等故障演练。
- 公开发布前进行项目内安全检查，尤其检查 Helper、签名、制品解包和密钥管理。

---

## 12. 最小可执行开发流程（从 0 到 V1）

阶段编号和退出条件以[分阶段开发流程](./phased-development-workflow.md)为准：

- **阶段 0—1**：设计基线、Master 和空 Agent 身份；工程状态与未完成验证见[实施状态](./phase-0-1-implementation.md)。
- **阶段 2**：签名任务、持久化恢复和只读 Helper；验证授权、篡改、重放及越权拒绝。
- **阶段 3**：Xray 可信安装、启停、升级、回滚，以及 Agent/Helper 自身更新与恢复基础。
- **阶段 4**：先为 Xray 实现签名配置、入站、用户、实际连接、可用统计、额度和订阅，完成端到端最小演示；统计不可靠时显示 `UNSUPPORTED` 并禁用精确额度。
- **阶段 5**：演示跑通后整理安装方式，开发并验证 Docker 构建，明确容器与宿主 Agent/Helper/systemd 的边界。
- **阶段 6**：接入 sing-box 和 mita，逐版本验证配置、用户、统计、恢复及共存隔离。
- **阶段 7**：完整 V1 安全测试、故障演练、发布及运行手册。

最小演示不是完整 V1 或生产发布批准；后续 Core 和发布验收仍需各自证据。

---

## 13. 第一批 GitHub Issues（建议）

| Issue | 标题 | 依赖 | 优先级 |
|---|---|---|---|
| AG-001 | 定义注册与证书绑定协议 | 无 | P0 |
| AG-002 | 实现 Agent 安全密钥存储与 mTLS | AG-001 | P0 |
| AG-003 | 实现任务 JSON Schema / JCS / Ed25519 | 无 | P0 |
| AG-004 | 实现任务序号、幂等、WAL 和恢复 | AG-003 | P0 |
| AG-005 | 实现 Helper UDS 身份与授权模型 | AG-003 | P0 |
| AG-006 | 实现受限 Core 文件操作与 systemd 管理 | AG-005 | P0 |
| AG-007 | 定义并验证可信 Core 发布清单 | 无 | P0 |
| AG-008 | 实现制品下载限制、安全解包与摘要校验 | AG-007 | P0 |
| AG-009 | 实现 CoreManager 安装事务与 LKG | AG-006, AG-008 | P0 |
| AG-010 | Xray CoreAdapter | AG-009 | P0 |
| AG-011 | sing-box CoreAdapter | Xray 闭环及安装/构建验证 | P0 |
| AG-012 | mita CoreAdapter | Xray 闭环及安装/构建验证 | P0 |
| AG-013 | 配置 revision 签名、验证与对账 | AG-003, AG-009 | P1 |
| AG-014 | 统计采集、Outbox 和主控去重 | 先 AG-010；其他 Core 接入后逐一验证 | P1 |
| AG-015 | 安全测试、故障注入、CI 发布门槛 | 全部 V1 交付项 | P0 |

---

## 14. V1 上线判定标准（Definition of Done）

上线前至少满足下列全部条件：

- [ ] **空安装**：Agent 首次安装无 Xray、sing-box、mita，未预置任何 Core 进程。
- [ ] **身份可信**：Agent 只信任已绑定 Master，mTLS 节点可吊销、凭据可轮换。
- [ ] **任务可信**：所有有副作用操作均来自签名任务，Node 绑定、防重放、过期和幂等可测。
- [ ] **Helper 最小权限**：不存在任意 Shell/路径/Unit 管理能力，其他本地用户不可越权调用。
- [ ] **制品可信**：三种 Core 仅能从可信签名清单选择安装；恶意包、错误摘要、错误架构一律拒绝。
- [ ] **进程隔离**：Agent 与 Core 使用不同非 root 账户，Core 读取不到 Agent 凭据。
- [ ] **安全恢复**：失败升级不破坏 LKG；无法恢复时明确失败并中止危险重试。
- [ ] **通信失联**：主控断连不会导致已运行正常 Core 被无故停止。
- [ ] **审计完善**：能关联管理员操作 → 主控授权 → Task ID → Agent 执行步骤 → Helper 结果。
- [ ] **版本兼容**：Xray、sing-box、mita 版本能力明确，未验证的统计/热更新不宣称支持。
- [ ] **安全测试**：第 11 章高危用例通过，无未解决的 P0 安全缺陷。
- [ ] **配置安全**：签名但越过节点配置策略的内容被拒绝；候选 Core/配置预检不以 root 执行。
- [ ] **管理面安全**：服务端操作/对象级鉴权、审批签发链、会话撤销和 CSRF 测试通过。
- [ ] **自身更新**：Agent/Helper 独立授权、健康确认、自动回滚和本地人工恢复通过实机故障演练。
- [ ] **完整 V1 业务**：入站、用户、订阅与可用统计能力达到项目大纲第 12 章；不支持统计的 Core 不启用精确额度控制。

---

## 15. 尚待团队明确的设计问题

这些是**编码前应形成决议**的少量问题，不应在开发中随意漂移：

1. **信任根部署**：采用证书 CA 固定根，还是 Master SPKI Pin；如何安全轮换。
2. **任务和制品签名体系**：正式采用 JCS + Ed25519，还是 TUF 元数据体系；钥匙由谁保管。
3. **高危操作审批**：卸载、降级、Agent/Helper 更新、信任根变更是否必须双人审批（推荐至少更新信任根需要独立授权）。
4. **本机权限管理**：Helper 使用独立 root 守护进程还是严格限定的 systemd 激活服务；V1 建议后者可按需启动，但仍要实现完整授权。
5. **mita 配置持久化**：指定支持版本的配置存储、replace/reload 与回滚边界如何验证。
6. **Core 版本策略**：只批准明确测试过的稳定版本；旧版安全回退最长保留多久。
7. **业务连续性**：节点被吊销/离线时默认继续维持现有 Core 多久，以及如何安全关停。
8. **统计精度**：若某个 Core 不支持可靠用户级增量计数，UI 如何标记“不支持/不完整”。
9. **配置策略**：每个 Core 的哪些监听、文件、管理 API、外部资源和出站字段可由主控管理，锁定版本如何维护。
10. **审批签发**：操作人与审批人的角色边界、审批有效期/使用次数、独立签发服务和签名密钥托管方式。
11. **自身更新监督**：选择能在新版本无法启动时自动恢复旧版本的本地监督实现，并验证数据库/协议兼容。

---

## 16. 参考与核对来源

以下链接用于核对上游项目能力和安全机制；**具体命令与特性仍需按实际锁定版本再次测试**。

1. [miaomiaowuX — 主控/Agent 结构](https://github.com/iluobei/miaomiaowuX)
2. [Xray — 官方命令说明（`run -test`）](https://xtls.github.io/document/command)
3. [sing-box — 官方配置与检查命令](https://sing-box.sagernet.org/zh/configuration/)
4. [mieru — 官方仓库（`mieru` 客户端 / `mita` 服务端）](https://github.com/enfein/mieru)
5. [mieru — 服务端配置及生命周期](https://github.com/enfein/mieru/blob/main/docs/server-install.md)
6. [mieru — 运维、用户流量和配额](https://github.com/enfein/mieru/blob/main/docs/operation.zh_CN.md)
7. [The Update Framework — 软件更新安全规范](https://theupdateframework.github.io/specification/latest/)
8. [systemd.exec — 系统服务权限与沙箱](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec)
9. [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)

---

**总结：**Agent 最重要的产出不是“能远程下载并执行 Core”，而是一个可以验证、可以拒绝、可以审计、可以回滚的**受限远程任务执行引擎**。把身份、签名、特权操作和恢复机制先做好，再接入 Xray / sing-box / mita 的配置和业务能力，才符合“安全第一、轻量化、主控—子节点”的项目定位。
