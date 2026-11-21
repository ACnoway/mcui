# Xray 远程生命周期的运维授权与独立签发

安装提案使用格式 3，启停使用格式 4，升级、降级和卸载使用格式 5。节点继续用专用生命周期公钥核验任务、租约和精确参数。历史 TUF 任务按原清单收尾。[制品发布](./phase-3-release.md)

## 单管理员面板签发

启用单管理员部署和现有状态任务运行时，并按[节点部署步骤](./phase-3-operations.md#5-启用远程-xray-安装)配置节点的生命周期公钥、发布公钥、NTS 时间和 Xray 状态目录。升级 Agent 及 Helper 后，面板从已认证心跳取得节点架构和 Helper 读出的已提交版本。状态缺失、过期或等待对账时，面板暂停操作。

面板与独立的生命周期签发进程都读取受保护的策略文件。举例，以下策略允许列出的节点使用后台签发。需要允许新建节点时，显式配置 `"panel": {"all_nodes": true}`。

```json
{
  "schema_version": 1,
  "signing_key_id": "xray-lifecycle",
  "signing_public_key": "<Xray 签发公钥的标准 Base64>",
  "panel": {"node_ids": ["node-00000000000000000000000000000000"]}
}
```

从同一发布提交构建 `mcui-lifecycle`。签发进程使用独立账号，保管 `0600` 的生命周期签发私钥和私有账本。配置经过校验的发布清单及其分离签名，并以签发账号使用 `mcui-manifest init-state` 预置[防回滚状态](./phase-3-release.md)。签发端使用 Cloudflare NTS 认证时间，签发账号需获准查询本机 `/run/chrony/chronyd.sock`。面板与签发进程共用一份高熵 API Token，文件使用 `0600` 或 `0640`。

```sh
mcui-lifecycle init-ledger -ledger /var/lib/mcui-xray-signer/issuance.db
mcui-lifecycle serve -listen 127.0.0.1:9232 \
  -policy /etc/mcui-xray-signer/policy.json \
  -key /etc/mcui-xray-signer/signing.pem \
  -ledger /var/lib/mcui-xray-signer/issuance.db \
  -token-file /etc/mcui-xray-signer/token \
  -release-key /etc/mcui-xray-signer/release.pub \
  -manifest-state /var/lib/mcui-xray-signer/manifest \
  -manifest /etc/mcui-xray-signer/manifest.json \
  -manifest-signature /etc/mcui-xray-signer/manifest.json.sig
```

面板配置 `MCUI_XRAY_INSTALL_POLICY`、`MCUI_XRAY_PANEL_SIGNER_URL=http://127.0.0.1:9232` 和 `MCUI_XRAY_PANEL_SIGNER_TOKEN_FILE`。也可使用同名功能的命令行参数。Compose 部署通过覆盖文件挂载配置并传入任务运行时参数，签发进程与 Master 共享容器网络的回环接口。签发器依赖 Master 核验会话和 MFA，并独立核对签发策略、任务参数、期限和制品清单。节点继续独立校验签名和制品。

在面板节点详情选择操作。安装、升级和降级只显示该节点架构可用的稳定版本，默认选中当前操作下的最新版本。降级和卸载显示目标版本并单独确认，要求输入 TOTP 验证码。签发或投递遇到暂时错误时，在有效期内使用同一请求重试。已到期且未投递的预留序号可通过只读状态任务收尾。

## 范围运维员手工签发

手工流程由具备节点范围的同一运维员发起、上传签发任务并投递。面板对写操作校验 MFA 和 CSRF。独立签发工具核验运维员对精确参数的签名和节点范围，并记录签发。[V1 授权](./panel-authz.md#v1-单管理员)

## 1. 配置授权策略

运维员保管自己的 Ed25519 私钥，签发服务保管独立于状态任务签发和制品发布的 Xray 安装任务私钥。通过独立渠道核对公钥指纹、账号 ID 和允许操作的节点。策略可只有一个运维员，各运维员使用不同公钥。示例值需替换为实际信任材料。

```json
{
  "schema_version": 1,
  "signing_key_id": "xray-install-key-1",
  "signing_public_key": "<专用签发公钥>",
  "principals": [
    {"id": "operator-1", "role": "operator", "public_key": "<运维公钥>", "node_ids": ["node-example"]}
  ]
}
```

公钥使用标准带填充 Base64 编码的 32 字节 Ed25519 公钥。私钥使用 Ed25519 PKCS#8 PEM 和 `0600` 权限。主控和签发服务各自加载可信策略。需要撤销范围时更新两端的策略副本并重新加载。现有策略里的 `security_admin` 条目可在迁移时删除。

主控启用 HTTPS、Cloudflare NTS 认证时间和任务运行时，再通过 `-xray-install-policy /etc/mcui/xray-install-policy.json` 或 `MCUI_XRAY_INSTALL_POLICY` 指定权限受保护的策略文件。策略中的运维员 ID 须匹配面板账号 ID，节点须在策略和面板账号的共同范围内。单机可使用同一台主机上的独立账号运行签发工具和保存账本。[单机备份恢复](./phase-2-operations.md#单机运行与备份恢复)

## 2. 创建并签署请求

1. 在已接入的节点详情页填写获审核的版本、架构、SHA-256 和当前签名制品清单的 `manifest_version`。通过 MFA 复验创建并下载 `proposal.json`。节点队列空闲时才可预留序号。提案格式为 V3，有效期 30 分钟。
2. 发起启动或停止时，选择对应操作，填写节点已安装版本、架构与 SHA-256。启停提案不填写制品清单版本。
3. 升级或降级提案同时填写当前版本与摘要，以及目标版本、摘要和签名清单版本。卸载提案填写将卸载的已安装版本、架构与摘要。
4. 运维员核对提案后使用自己的密钥签署。请求签名覆盖完整提案及请求时间。

```sh
go build -trimpath -o mcui-lifecycle ./cmd/mcui-lifecycle
umask 077
./mcui-lifecycle request -policy policy.json -key "$OPERATOR_KEY" -input proposal.json > request.json
```

## 3. 持久化签发并投递

签发端由获准访问 `/run/chrony/chronyd.sock` 的账号执行。工具检查认证 NTS 时间、当前策略及请求签名。任务从运维员签署请求时起生效，在签署后 10 分钟或提案到期时失效，以较早者为准。

```sh
./mcui-lifecycle init-ledger -ledger "$SIGNER_LEDGER"
./mcui-lifecycle issue -policy "$TRUSTED_POLICY" -key "$INSTALL_SIGNING_KEY" \
  -input request.json -ledger "$SIGNER_LEDGER" > signed-task.json
```

`init-ledger` 只用于首次创建账本。恢复主控数据库时保留签发账本的当前版本。任务 ID、请求摘要和节点序号各自唯一，SQLite 提交后才输出任务。请求仍有效且当前策略仍允许时，使用同一份 `request.json` 重试会返回字节相同的任务。若无法确认账本的新鲜度，暂停签发，并核对主控和节点账本。启用了独立检查点的部署也要核对检查点记录。

原发起运维员在面板上传原始 `request.json` 和 `signed-task.json`。主控核对当前范围、已预留提案、两份签名和全部任务字段，保存后显示“已核验签发任务”。启用了独立检查点时，状态还会在返回前写入检查点。同一运维员在有效期内投递相应任务。降级与卸载分别核对目标后确认，投递请求的 `confirm_operation` 必须等于签名任务的对应操作。目标节点须先按[节点部署步骤](./phase-3-operations.md#5-启用远程-xray-安装)配置。

提案占用序号至到期。若到期时该槽仍空闲，在节点完成一次只读状态查询以消费该序号，再创建新提案。这样可以避开签发账本可能已经消费过的槽。

## 4. 从旧流程迁移

升级主控与签发 CLI 后使用新提案。历史 V1 提案及审计保留，已投递任务沿用原签名和结果回报路径，未投递的旧提案到期后按上述步骤重新申请。节点任务信封、专用签发公钥和 SQLite 结构保持兼容。信封保留 `approval_id` 字段，新任务在此字段中携带运维员签名请求的摘要。
