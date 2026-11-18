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

- 任务库与审计库仍是两个 SQLite 事务域。主控可显式启用独立检查点，在启动和数据 API 前核对两库摘要及外部 revision，并在对外返回任务、租约、凭据或更新结果前确认新 revision。旧备份或不匹配的 intent 会冻结操作。检查点存储与运维须独立于主控恢复域。[检查点部署与恢复](./phase-2-operations.md#8-部署独立检查点)
- 数据库提交后、intent 落盘前的异常仍需带外核对。已持久化的 intent 只有在其目标摘要与两库一致时才可续做。未配置检查点的既有主控继续使用任务/审计对账。
- 序号恢复仅覆盖可证明的过期终态历史和已持久化 `VOID_UNISSUED` 槽。活动任务、未过期历史任务、运行中/结果未决任务和无法证明的缺口继续隔离；不支持通用 `CANCELED` skip，也不从备份自动恢复 Agent/Helper 的任务结果。
- 可信时间运行时依赖部署主机的 chrony 已配置 NTS 且只读监控命令可从 loopback 使用。源不可用、NTS 认证失效、样本过旧或偏差过大时，任务创建、轮询、执行和 ACK 会失败关闭。它不等于独立硬件时间根或防止同时篡改本地 chrony/系统状态的安全审计。
- 真实节点上的 peer credentials、root Helper 沙箱、目标 Core 状态读取、断电恢复和项目安全审核仍待整体验收。

## 验证状态

| 检查 | 当前结果 | 说明 |
|---|---|---|
| Go 格式检查 | 通过 | 本地改动运行 `gofmt`；远端脚本检查全部 `cmd/`、`internal/` Go 文件 |
| `git diff --check` | 通过 | 每次提交前检查 |
| 本地静态检查 | 通过（`1ba38ce`） | 临时工具链环境通过 Linux Go vet、amd64/arm64 交叉构建、协议向量、检查点状态机测试和 Web 类型/生产构建。Windows 上 pnpm 冻结安装进程发生栈溢出，Web 构建使用已有依赖 |
| `scripts/check-static.sh` 远程构建与测试 | 通过（`1ba38ce`，2026-11-18） | `ro:/root/mcui`，Debian 13.7 amd64；Go 1.27.4、Node.js 26.13.1、pnpm 12.17.0。Go vet、全量 Go 测试、Linux 双架构构建、协议向量、冻结安装和 Web 构建通过 |
| 检查点竞态与恢复测试 | 通过（`1ba38ce`） | `go test -race -count=1 ./internal/checkpoint ./internal/checkpointstore ./internal/checkpointjournal ./internal/checkpointhttp`；覆盖旧 journal 拒绝、CAS 幂等、认证和挑战不匹配 |
| 检查点 systemd 冒烟 | 通过（`1ba38ce`） | `ro` 的 systemd 257.13 环境，使用临时 unit、隔离账号、loopback 和测试证书。验证重复初始化被拒、无证书和未登记公钥被拒、revision 递增及服务重启后可读。临时资源已清理 |
| 主控双库检查点、全量检查和竞态测试 | 通过（`405771d`，2026-11-18） | `ro:/root/mcui`，Debian 13.7 amd64。全量 `scripts/check-static.sh` 与 `go test -race -count=1 ./internal/master ./internal/store ./internal/taskdispatch ./internal/checkpoint ./internal/checkpointstore ./internal/checkpointjournal ./internal/checkpointhttp` 通过。集成测试覆盖签发、租约、协调旧备份、远端提交响应丢失和未匹配 intent |
| 主控与检查点进程恢复演练 | 通过（`405771d`） | `ro` 上用实际二进制、临时 SQLite 文件和测试证书，通过 mTLS 验证主控提交推动外部 revision。同一 journal 拒绝第二个主控进程，检查点离线时数据 API 返回 503，恢复连接后重新可用。当前两库可重启，旧两库搭配当前及旧 journal 均被拒，独立端 revision 保持。测试进程和文件已清理 |

## 阶段退出门槛

阶段 2 尚未通过退出门槛。仍需在隔离的 Debian 13.7 amd64 环境验证真实 peer credentials、固定 systemd 查询和系统沙箱；覆盖 cancel/start 竞争、伪造控制、重放、过期、租约竞争、ACK 丢失、旧库迁移、断电和状态库恢复；核验双库备份回滚、NTS 部署和 Agent/Helper 本地状态恢复；完成项目内安全检查及责任人签核。
