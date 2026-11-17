# 阶段 2 进度与未完成项

**状态：只读状态查询及受限签名控制运行时已接通；阶段验收未完成。** 本记录区分代码实现、自动化检查与正式退出门槛。当前唯一可执行任务是签名的 `core.status` 查询；cancel 仅能取消尚未开始的状态任务，skip 仅能确认已过期状态任务，不开放任何系统变更。V2 协议语义见[协议草案](./phase-2-protocol-draft.md)，安装/启用步骤见[阶段 2 操作说明](./phase-2-operations.md)。

## 已接通的运行路径

- Master 管理 API 提供只读状态任务的创建、列表和详情；每次创建重新验证当前账号、角色、节点状态及节点范围。仅 `security_admin` 和 `operator` 可发起，`auditor` 只可读取。V2 固定绑定 Core 名称和 `core.status` 步骤。
- 任务数据库在事务中分配连续节点序号、调用独立签名进程并保存已验签的完整消息；如果签名失败，事务回滚且序号不前进。只读请求无需单独审批，授权审计先于任务入队，任务来源、授权时间与“无需单独审批”显示在面板。
- Agent 通过现有 mTLS 身份轮询和回传 ACK。任务先验签并写入私有 SQLite 账本，再进入 Helper；ACK 历史按版本幂等重放。已过期但签名、目标和序号有效的任务仅写为 `EXPIRED`，不会调用 Helper；`RUNNING` 状态重启后改为 `NEEDS_RECONCILIATION` 并保持序号栅栏。
- 管理面板为 `security_admin`/`operator` 提供受范围控制的 pending cancel 与 expired skip。Signer 使用 V1 独立域签名控制信封；Master 在独立控制表持久化信封并撤销旧投递租约。Agent 在原任务收件后验签控制：cancel 与账本取消墓碑/状态转换同一 SQLite 写事务竞争；skip 只接受 `EXPIRED`，且要求任务已在 Agent 账本终态过期。控制 ACK 与普通任务 ACK 一样可幂等重放。
- 既有 Master 任务库经过完整旧 schema 与数据检查后，会在 `Open` 时以事务增建隔离的 `task_controls` 表，保留原任务与 ACK；其他 schema 偏差仍拒绝启动。
- Helper 只接受 Agent Unix Socket 连接，按内核 peer UID 验证对端；重新验证签名、目标、密钥用途、操作、期限和固定字段映射。执行前向 Master 发起 TLS 1.3 检查点请求，要求提交的原始签名消息与当前 60 秒租约完全一致，并确认前序任务已全部终结。
- Helper 将当前任务写入 root 私有账本后，才使用固定的 `/usr/bin/systemctl show` 参数读取三种固定服务之一。请求不能提供 shell、路径、unit、URL、参数或制品信息；只返回固定字段的状态 JSON。重复查询返回账本中的同一结果，未决执行或账本不一致则失败关闭。
- 已添加 Agent、Helper、Master 和隔离签名进程的 systemd 部署单元/覆盖文件。签名私钥留在独立 signer 账号；Master 与 signer 通过受限 loopback HTTP 和共享 token 通讯。

## 与完整协议的差异和剩余安全边界

- 控制消息仅实现状态查询子集：cancel 只能请求未过期且未开始的 `core.status`，已开始或结果未决的任务不会被报告为成功取消；skip 仅支持 `EXPIRED`，以原任务的已持久化终态消费序号。`VOID_UNISSUED`、独立 `CANCELED` skip、通用序号缺口补偿及签名 skip 槽恢复未实现；无法解释的缺口继续失败关闭。
- Helper 检查点来自 Master 的当前任务库、租约和系统时钟。它能与节点本地账本分开核对，但没有接入独立外部可信时间服务；协调回滚 Master 状态库和时间源不在现有保证范围内。Helper 本地账本本身仍与其时间高水位处于同一回滚域。
- Master 任务 SQLite 与主控身份/审计 SQLite 分开提交，无法跨库原子提交。授权审计先落盘以避免完全无审计的签发；签发审计为后置尽力记录，仍需将两库一致性、备份/恢复及崩溃恢复纳入专项验收。
- 失败结果对当前无副作用的状态任务按终态处理；未来任何会改变系统的任务必须重新定义失败、回滚和终态语义，不能复用本规则。
- 代码与组件测试不能证明 Root Helper 在受支持发行版、systemd 版本和真实 Core 服务上的系统调用边界、权限及可用性。

## 验证状态

| 检查 | 当前结果 | 说明 |
|---|---|---|
| 本地 `gofmt`（仅本次 Go 文件） | 通过 | 本机仅格式/解析检查，没有安装或修改工具链 |
| 本地 `git diff --check` | 通过 | 每次推送前检查 |
| 本地 V1/V2 共享向量脚本 | 通过 | V1 4 个正例、9 个负例；V2 3 个正例、29 个负例 |
| 完整 `scripts/check-static.sh` | 通过 | `ssh ro` 的 `/root/mcui`，Debian 13 amd64；Go 1.27.4、Node.js 26.13.1、pnpm 12.17.0。包含 Go vet/build/test、Linux amd64/arm64 交叉构建、协议向量和前端冻结依赖安装/类型检查/生产构建 |
| systemd unit 语法检查 | 通过 | systemd 257.13 临时 sysroot 验证四个服务和两个 task-runtime drop-in；未安装或启动服务 |
| Linux 实际 Helper / Core 端到端演练 | 未完成 | 远程构建环境不等同于干净节点验收 |

## 阶段退出门槛

阶段 2 当前仍未通过退出门槛。还需在 Debian 13.7 amd64/arm64 环境验证真实 peer credentials、固定 systemd 查询和系统沙箱；覆盖 cancel/start 竞争、伪造控制、重放、过期、租约竞争、ACK 丢失、旧库迁移、断电和状态库恢复；验证无法解释的序号缺口保持隔离；检查签发与审计双库一致性；完成项目内安全检查与责任人签核。阶段退出或生产授权须另行记录，不由本次代码构建结果推定。
