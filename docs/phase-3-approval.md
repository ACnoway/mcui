# Xray 安装的运维授权与独立签发

Xray 远程安装由同一名具备节点范围的运维员发起、上传签发任务并投递。面板对这些写操作要求 MFA 复验和 CSRF 校验。独立签发工具校验运维员对精确参数的签名和节点范围，并在受保护的账本中记录签发。新提案采用格式版本 3，绑定单签名制品清单的 `manifest_version`。历史 TUF 任务按原清单收尾。[制品发布](./phase-3-release.md)

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

主控启用 HTTPS、认证时间和[独立任务检查点](./phase-2-operations.md#8-部署独立检查点)，再通过 `-xray-install-policy /etc/mcui/xray-install-policy.json` 或 `MCUI_XRAY_INSTALL_POLICY` 指定权限受保护的策略文件。策略中的运维员 ID 须匹配面板账号 ID，节点须在策略和面板账号的共同范围内。

## 2. 创建并签署请求

1. 在已接入的节点详情页填写获审核的版本、架构、SHA-256 和当前签名制品清单的 `manifest_version`。通过 MFA 复验创建并下载 `proposal.json`。节点队列空闲时才可预留序号。提案格式为 V3，有效期 30 分钟。
2. 运维员核对提案后使用自己的密钥签署。请求签名覆盖完整提案及请求时间。节点 ID、序号、制品和委派版本均由签名绑定。

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

`init-ledger` 只用于首次创建账本。账本保存在主控备份恢复域之外。任务 ID、请求摘要和节点序号各自唯一，SQLite 提交后才输出任务。请求仍有效且当前策略仍允许时，使用同一份 `request.json` 重试会返回字节相同的任务。若账本的新鲜度无法证明，暂停签发并由签发方和主控检查点保管方对账。

原发起运维员在面板上传原始 `request.json` 和 `signed-task.json`。主控核对当前范围、已预留提案、两份签名和全部任务字段，经检查点确认后显示“已核验签发任务”。同一运维员在有效期内点击“投递安装任务”。目标节点须先按[节点部署步骤](./phase-3-operations.md#5-启用远程-xray-安装)配置。

提案占用序号至到期。若到期时该槽仍空闲，在节点完成一次只读状态查询以消费该序号，再创建新提案。这样可以避开签发账本可能已经消费过的槽。

## 4. 从旧流程迁移

升级主控与签发 CLI 后使用新提案。历史 V1 提案及审计保留，已投递任务沿用原签名和结果回报路径，未投递的旧提案到期后按上述步骤重新申请。节点任务信封、专用签发公钥和 SQLite 结构保持兼容。信封保留 `approval_id` 字段，新任务在此字段中携带运维员签名请求的摘要。
