# Agent 与 Helper 成对更新

安全管理员可在 Master 提交已离线签名的成对更新，节点管理员也可通过本地 systemd 提交。独立监督器使用现有双架构 ZIP，将每个版本放入 root 管理的只读目录，再通过同一个版本指针切换两个服务。Agent 和 Helper 的身份、账本及配置路径沿用原部署。

## 启用本地监督

1. 在隔离节点使用已核验的同版源码构建 Agent、Helper 和 `mcui-runtime`。按既有部署流程将该 Agent 和 Helper 作为已知可用的基线部署至 `/usr/local/bin`。保留节点身份与现有账本。
2. 带外核验两把独立公钥的指纹。将发布公钥和节点更新授权公钥分别装到 `/etc/mcui-runtime/release.pub` 和 `/etc/mcui-runtime/update.pub`。两把密钥独立于日常任务签发和 Core 发布。第一次初始化时，监督器把这两把公钥绑定到节点状态。
3. 安装监督器和 systemd 单元，初始化基线。将配套 drop-in 命名为 `zz-paired-runtime.conf`，使它在现有任务配置之后接管 `ExecStart`。

```sh
go build -trimpath -o mcui-runtime ./cmd/mcui-runtime
install -o root -g root -m 0755 mcui-runtime /usr/local/bin/mcui-runtime
mcui-runtime init -node-id "$NODE_ID" -version "$CURRENT_VERSION"
install -o root -g root -m 0644 deploy/systemd/mcui-runtime-{recover,update}.service /etc/systemd/system/
install -d /etc/systemd/system/mcui-agent.service.d /etc/systemd/system/mcui-helper.service.d
install -m 0644 deploy/systemd/mcui-agent-paired-runtime.conf /etc/systemd/system/mcui-agent.service.d/zz-paired-runtime.conf
install -m 0644 deploy/systemd/mcui-helper-paired-runtime.conf /etc/systemd/system/mcui-helper.service.d/zz-paired-runtime.conf
systemctl daemon-reload
systemctl stop mcui-agent.service mcui-helper.service
systemctl start mcui-helper.service mcui-agent.service
mcui-runtime status
```

两项服务通过启动检查后才准备更新。开机时，两个服务都等待 `mcui-runtime-recover.service` 恢复已提交的共同指针。仅在成对更新结论持久化后，候选 Agent 才恢复任务轮询，Helper 才重新处理任务。

## 签发更新

1. 使用 `bash scripts/build-runtime-release.sh NEW_DIRECTORY` 构建成对 ZIP。发布保管人审核两个可执行文件，创建只包含 `mcui-runtime` 条目的[制品清单](./phase-3-release.md#2-取件核验和发布)，用独立运行时发布密钥执行 `mcui-manifest sign`。
2. 更新授权保管人核对节点的 `mcui-runtime status`。签名请求绑定节点 ID、当前成对 SHA-256、递增授权序号、精确清单版本与原文 SHA-256、候选版本、架构和 ZIP SHA-256，以及不超过 24 小时的有效窗口。状态协议固定为本节支持的 `1`。

```json
{
  "schema_version": 1,
  "state_protocol": 1,
  "node_id": "node-example",
  "sequence": 1,
  "current_pair_sha256": "<mcui-runtime status 的 current_pair_sha256>",
  "manifest_version": 1,
  "manifest_sha256": "<manifest.json 的 SHA-256>",
  "version": "v1.0.1",
  "architecture": "amd64",
  "sha256": "<候选 ZIP 的 SHA-256>",
  "not_before": "<授权生效时间，RFC 3339>",
  "expires_at": "<授权到期时间，RFC 3339>"
}
```

```sh
mcui-runtime sign -private-key "$UPDATE_PRIVATE_KEY" \
  -input authorization.json -signature authorization.json.sig
```

3. 以 root 将 `manifest.json`、`manifest.json.sig`、`authorization.json`、`authorization.json.sig` 和本架构成对 ZIP 放入 `/var/lib/mcui-runtime/incoming`，使用 `0600` 权限。按[认证时间配置](./phase-2-operations.md#11-配置认证-nts-时间)启用 NTS。
4. 待节点任务收尾，执行 `systemctl start mcui-runtime-update.service`。查看 `mcui-runtime status` 和 `journalctl -u mcui-runtime-update.service`。监督器用独立公钥验两份签名，拒绝旧序号、清单回退和同版清单内容冲突。ZIP 仅接受两项固定成员，并校验长度、散列和 ELF 架构。

## 从 Master 发起更新

1. Master 启用 HTTPS、[认证 NTS 时间](./phase-2-operations.md#11-配置认证-nts-时间)和[独立检查点](./phase-2-operations.md#8-部署独立检查点)。在已启用本地监督的节点生成一个独立随机凭据。凭据归节点 root 管理，Master 策略保存凭据原文的 SHA-256。

   ```sh
   install -d -o root -g root -m 0700 /etc/mcui-runtime
   ( set -o noclobber; umask 077; openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' > /etc/mcui-runtime/supervisor.token )
   sha256sum /etc/mcui-runtime/supervisor.token
   ```

2. Master 增加 `-runtime-update-policy /etc/mcui/runtime-update.json`，使用 systemd 的部署可以在 `panel-task-runtime.env` 设置 `MCUI_RUNTIME_UPDATE_POLICY`。配置由部署管理员写入，授权运行账号只读。两个公钥字段为 Ed25519 原始 32 字节公钥的标准 Base64，和初始化节点时核验的公钥相同。

   ```json
   {
     "release_key": "<发布公钥的标准 Base64>",
     "authorization_key": "<节点更新授权公钥的标准 Base64>",
     "archive_dir": "/var/lib/mcui/runtime-releases",
     "node_token_sha256": { "node-example": "<节点监督器凭据的 SHA-256>" }
   }
   ```

   由发布管理员校验 ZIP 与已签清单一致，再将 ZIP 放入 `archive_dir`，文件名为 `<ZIP 的 SHA-256>.zip`。Master 账号需能读目录和文件。目录和文件禁止组及其他账号写入。保持已投递版本的文件，直到对应更新结案。

3. 在节点的 `/etc/mcui-runtime/remote.env` 写入受信 HTTPS 地址 `MCUI_MASTER_URL`，使用私有 CA 时将 `MCUI_SERVER_CA` 指向 root 管理的 CA 文件。使用系统 CA 时该值可为空。将 [systemd 服务](../deploy/systemd/mcui-runtime-remote.service)和[定时器](../deploy/systemd/mcui-runtime-remote.timer)安装到 `/etc/systemd/system/`，执行以下命令。

   ```sh
   systemctl daemon-reload
   systemctl enable --now mcui-runtime-remote.timer
   ```

4. 安全管理员打开面板中的目标节点，在 **Agent / Helper 成对更新** 提交两份 JSON 原文和两个 64 字节分离签名，按提示完成 MFA。API 客户端也可向 `POST /api/v1/admin/nodes/<node_id>/runtime-updates` 提交，沿用管理员会话、Origin、CSRF 和 MFA。请求体为 `{"package":{"authorization":"...","authorization_signature":"...","manifest":"...","manifest_signature":"..."},"mfa_code":"..."}`，四项材料分别以标准 Base64 传输原始字节。返回的 `id` 是授权原文的 SHA-256。重复提交同一授权可查询原记录。使用同一路径的 GET 或面板的 **刷新结果** 查看进度。

5. 节点 root 监督器通过 TLS 1.3 主动领取，使用独立凭据从配置的 Master 获取归档，并复验签名、有效期、架构和精确字节。Master 在同一节点存在已投递的状态查询、Xray 任务或另一项成对更新时拒绝新更新；从更新入队到收到节点终态期间，暂停该节点的新任务。已领取记录等待节点回执，即使授权随后过期；监督器提交、回退或拒绝后持久化结果，断网或回执丢失时自动重报。未领取的过期授权可由新序号替换。

远程更新默认关闭。在发布验收前仅在隔离节点启用。检查停在「已领取」的记录时，核对 `journalctl -u mcui-runtime-remote.service`、节点 `mcui-runtime status`、连通性及 NTS。必要时先暂停定时器，按本地修复流程恢复节点，再恢复轮询以回报已保存的结果。

## 启动检查与回退

- 候选 Agent 校验已接入的节点身份和现有账本，使用 Unix socket 核对 root Helper、节点 ID 和运行时协议。Helper 在开放 socket 前检查自身账本。存在未决任务时试运行失败，节点回到先前版本处理任务。
- systemd 观察两个候选进程完成就绪通知并保持 PID 稳定。监督器持久化成对提交后解除试运行限制。候选失败或超时会恢复旧指针并启动旧服务。进程异常终止时由 `ExecStopPost` 接手，开机时由恢复单元在两个服务启动前恢复旧指针。
- 本地恢复可执行 `mcui-runtime repair`，无需 Master。对已提交版本需要人工回退时，执行 `mcui-runtime revert` 试运行上一次提交的成对版本。回退保留已消费的授权序号和清单记录。遇到账本损坏或无法验证原有文件时，留存状态并按[人工修复说明](./phase-3-operations.md#4-agent-和-helper-本地人工修复)核验可信备份。
- 原有安装环境继续使用各自的 unit，主动启用配套 drop-in 后才由监督器管理。生产故障演练的状态见[阶段 3 进度](./phase-3-progress.md)。
