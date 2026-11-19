# Xray 安装的独立审批与签发

`mcui-lifecycle` 为精确的 Xray `core.install` 提案提供离线双签和单次签发。配置独立检查点与审批策略后，面板支持 MFA 复验、预留序号和登记双签审批。主控队列、Agent 和 Helper 当前仅投递和执行阶段 2 的状态查询。

## 1. 建立独立签发策略

运维员、安全管理员和 Xray 安装任务签发者各自保管 Ed25519 私钥。签发者使用独立于状态签发和 TUF 发布的专用密钥。由签发管理方通过独立渠道核对身份、公钥指纹和可管理节点，发布策略的受信副本。运维员与审批人需覆盖同一目标节点，且各自使用唯一身份和公钥。

`policy.json` 包含 `schema_version`（固定为 1）、`signing_key_id`、`signing_public_key` 和 `principals`。公钥为标准带填充 Base64 的原始 32 字节 Ed25519 公钥。每个 principal 包含 `id`、`role`、`public_key` 和 `node_ids`，角色分别为 `operator` 与 `security_admin`。节点范围逐个列 ID。下例中的值须替换为受信材料。

```json
{
  "schema_version": 1,
  "signing_key_id": "xray-install-key-1",
  "signing_public_key": "<专用签发公钥>",
  "principals": [
    {"id": "operator-1", "role": "operator", "public_key": "<运维公钥>", "node_ids": ["node-example"]},
    {"id": "approver-1", "role": "security_admin", "public_key": "<审批公钥>", "node_ids": ["node-example"]}
  ]
}
```

签发方在受保护目录以专用账号运行签发命令。私钥文件使用 Ed25519 PKCS#8 PEM 和 `0600` 权限。由签发管理方控制实际策略路径、账本路径和签发配置，面板与提案发起人仅传递审批文件。暂停签发后可原子替换策略以撤销身份、公钥或节点范围。签发时读取当前受信策略，失去范围的旧审批会被拒绝。

## 2. 提案与独立审核

在启用 HTTPS 与[独立检查点](./phase-2-operations.md#8-部署独立检查点)的主控上，将受信策略放在主控服务可读、服务账号不可写的目录。用 `-xray-install-policy /etc/mcui/xray-install-policy.json` 或在面板服务环境中设置 `MCUI_XRAY_INSTALL_POLICY` 后重启主控。策略的 principal ID 必须与面板账号 ID 一致。主控和独立签发方各自配置受信策略副本，策略变更后分别加载。

1. 运维员在已接入的测试节点详情页输入获审核的版本、架构、SHA-256、当前 `core-targets` 版本和安全管理员 ID。通过 MFA 复验后下载 `proposal.json`。只有节点队列空闲时才能预留序号。
2. 运维员和指定安全管理员各自使用下面的命令完成独立签署。审批人核对提案参数及制品审核证据，并在面板中上传 `approval.json`。主控重新核对角色、节点范围、签名、有效期和不可变提案，并在检查点确认后返回“已登记审批”。此状态表示主控已登记证明。
3. 每个预留槽持续至提案到期。到期前该节点无法建立新的只读任务。若提案过期，可在该节点完成一次只读状态查询，再创建新提案。这样可避免独立签发账本已记录同一槽时重复占用序号。

仅测试离线签发时，可以在隔离环境手工构造同样的提案。面板流程应使用下载的原始提案。时间字段用 Unix 秒表示，提案有效期最长 30 分钟。

```sh
created=$(date -u +%s)
cat > proposal.json <<EOF
{
  "schema_version": 1,
  "operation": "core.install",
  "core": "xray",
  "task_id": "$TASK_ID",
  "node_id": "$NODE_ID",
  "sequence": $SEQUENCE,
  "version": "$VERSION",
  "architecture": "$ARCH",
  "sha256": "$SHA256",
  "manifest_version": $CORE_TARGETS_VERSION,
  "requester_id": "$OPERATOR_ID",
  "approver_id": "$APPROVER_ID",
  "signing_key_id": "$SIGNING_KEY_ID",
  "created_at": $created,
  "expires_at": $((created + 1800))
}
EOF
```

`TASK_ID` 使用 22 至 128 字符的随机标识，字符集为英文字母、数字、下划线和连字符。版本使用 `v主版本.次版本.补丁版本`，架构为 `amd64` 或 `arm64`，摘要为小写十六进制 SHA-256。签发时生成与发布目标一致的 `xray-<架构>-<摘要>` 制品 ID，文件、来源 URL 和 Unit 由后续节点执行策略绑定。

分别在密钥持有人自己的环境执行命令。审批人验证请求签名与范围，再签署包含完整请求的审批。两份签名使用独立签名域。

```sh
go build -trimpath -o mcui-lifecycle ./cmd/mcui-lifecycle
umask 077
./mcui-lifecycle request -policy policy.json -key "$OPERATOR_KEY" -input proposal.json > request.json
./mcui-lifecycle approve -policy policy.json -key "$APPROVER_KEY" -input request.json > approval.json
```

## 3. 持久化签发并处理重试

账本由签发方单独保管，置于主控备份回滚域之外。首次初始化只能创建新文件。由获准访问 `/run/chrony/chronyd.sock` 的本地签发方读取 chrony NTS 认证状态，并检查两个角色、当前节点范围、显式任务密钥和提案/审批时限。任务在审批时刻起生效，最迟于审批后 10 分钟或提案到期时失效。

```sh
./mcui-lifecycle init-ledger -ledger "$SIGNER_LEDGER"
./mcui-lifecycle issue -policy "$TRUSTED_POLICY" -key "$INSTALL_SIGNING_KEY" \
  -input approval.json -ledger "$SIGNER_LEDGER" > signed-task.json
```

任务 ID、审批 ID 和节点序号各自唯一。签发在 SQLite 事务中持久化完整审批和签名任务，提交成功后才输出。有效期内、当前策略仍批准时，重试同一份审批返回相同字节。改换序号、内容或审批后重试已消费槽会被拒绝。如果账本丢失、回档或提交结果未知，保留证据，按原审批核对并重试。无法证明账本新鲜度时冻结签发，由签发方与主控检查点保管方对账。

签发完成后，由指定审批人在面板上传原始 `approval.json` 与 `signed-task.json`。主控核对受信专用签名、公钥用途、原先登记的审批摘要、序号、节点、完整制品参数和有效期。检查点确认后显示“已核验签发任务”。队列投递、节点执行、生产密钥保管及运行验收仍待完成。
