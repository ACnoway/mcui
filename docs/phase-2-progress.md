# 阶段 2 进度与未完成项

**状态：阶段 2 代码范围及远程自动构建验证已通过；正式阶段验收未完成。** 远程 `scripts/check-static.sh` 在 `be46e50` 通过。当前唯一可执行任务是签名的 V2 `core.status` 只读查询。所有任务时限和审计判断都要求认证 NTS 时间；Core 安装、启停、配置和任意命令仍未开放。V2 协议见[协议草案](./phase-2-protocol-draft.md)，部署与恢复步骤见[操作说明](./phase-2-operations.md)。

## 已接通的运行路径

- Master 为状态任务逐请求校验管理员身份、角色和节点范围；授权审计先于入队。独立 signer 只为固定 V2 状态任务签名。任务序号、完整签名消息和投递租约保存在独立任务库。
- Agent 使用其私有 SQLite 账本的 `next_sequence` 向 Master 报告期望序号。节点序号历史存在已过期终态时，Master 可返回对应原任务和签名 `EXPIRED` skip；Agent 验签后只消费该历史槽，不调用 Helper，也不重发已存在的终态 ACK。已签发但从未租出的任务可由面板签名 `VOID_UNISSUED` 关闭；Agent 以合成 `CANCELED` 墓碑原子消费空槽并 ACK。未知、活动或不可证明的缺口仍失败关闭。当前未实现独立 `CANCELED` skip。
- Agent 先验签并持久化任务再进入 Helper，ACK 历史按版本幂等重放。过期任务只写入 `EXPIRED`；`RUNNING` 重启后进入 `NEEDS_RECONCILIATION` 并保持序号栅栏。Helper 只接受 Unix Socket peer UID、独立签名校验、当前 Master TLS 检查点和有效租约；执行边界仅为固定 `systemctl show` 状态读取。
- Master、Agent 和 Helper 通过本机 chrony 检查 Cloudflare NTS。应用要求选中的来源精确为 `time.cloudflare.com`、最近样本不超过 300 秒、`authdata` 显示 NTS/有效 AEAD/cookie、tracking 为同步状态且误差界限不超过 1 秒；不接受未认证来源或本地时钟回退作为替代。Agent/Helper 还将本机 NTS 时间与 经 HTTPS 验证的 Master 时间比较，偏差超过 30 秒时拒绝处理。
- Master 启动前交叉核对任务库和主控审计库。缺少授权的任务、无任务的签发审计、签名任务与授权节点/Core 不符都会阻止启动。任务已经持久化但后置签发/关闭审计因进程崩溃而缺失时，在独立可信时间可用的前提下补写恢复审计。
- 控制表通过已知的加表迁移升级旧任务库；Agent 与 Helper 均保留私有账本。部署说明包括 NTS 配置、读状态 API、恢复边界与服务启动检查。

## 尚未解决的恢复和验收边界

- 任务库与审计库仍是两个 SQLite 事务域。启动时可以发现一边有记录而另一边缺失并恢复特定的后置审计，但没有跨库原子事务，也没有能识别两库同时回滚的独立单调检查点；协调恢复旧备份仍须隔离节点并带外核对。
- 独立检查点已有 `mcui-checkpointd` 测试部署入口。服务通过 TLS 1.3 双向认证，核对客户端公钥指纹，再由 SQLite 执行 revision 比较和递增。主控两库的提交和启动恢复仍待接入，检查点的存储与运维也需独立于主控恢复域。[检查点验证实例](./phase-2-operations.md#8-部署隔离的检查点验证实例)
- 序号恢复仅覆盖可证明的过期终态历史和已持久化 `VOID_UNISSUED` 槽。活动任务、未过期历史任务、运行中/结果未决任务和无法证明的缺口继续隔离；不支持通用 `CANCELED` skip，也不从备份自动恢复 Agent/Helper 的任务结果。
- 可信时间运行时依赖部署主机的 chrony 已配置 NTS 且只读监控命令可从 loopback 使用。源不可用、NTS 认证失效、样本过旧或偏差过大时，任务创建、轮询、执行和 ACK 会失败关闭。它不等于独立硬件时间根或防止同时篡改本地 chrony/系统状态的安全审计。
- 自动化构建不能证明真实节点上的 peer credentials、root Helper 沙箱、目标 Core 状态读取、断电恢复或安全边界。用户要求的实机演练和安全审核本次未进行。

## 验证状态

| 检查 | 当前结果 | 说明 |
|---|---|---|
| Go 格式检查 | 通过 | 本地改动运行 `gofmt`；远端脚本检查全部 `cmd/`、`internal/` Go 文件 |
| `git diff --check` | 通过 | 每次提交前检查 |
| 本地 Go 构建/测试 | 未运行 | 本机 Go wrapper 无法下载仓库指定工具链；依用户要求使用远程环境 |
| `scripts/check-static.sh` 远程构建与测试 | 通过（`be46e50`） | `ssh ro`，`/root/mcui`，Debian 13.7 amd64；Go 1.27.4、Node.js 26.13.1、pnpm 12.17.0。包含 `go vet`、全量 Go 测试、Linux amd64/arm64 构建、V1/V2 向量、冻结依赖安装、前端类型检查和生产构建 |
| systemd unit 语法检查 | 未单独重跑 | 本次提交没有修改 unit 或 drop-in 文件 |
| Linux 实机演练/安全审核 | 未进行 | 按本次范围明确排除 |

## 阶段退出门槛

阶段 2 尚未通过退出门槛。仍需在隔离的 Debian 13.7 amd64 环境验证真实 peer credentials、固定 systemd 查询和系统沙箱；覆盖 cancel/start 竞争、伪造控制、重放、过期、租约竞争、ACK 丢失、旧库迁移、断电和状态库恢复；核验双库备份回滚、NTS 部署和 Agent/Helper 本地状态恢复；完成项目内安全检查及责任人签核。
