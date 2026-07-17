# P4：在线激活、租约与撤销

## 目标

在不破坏离线主 License 信任模型的前提下，增加激活、订阅续租、浮动并发、可信时间和撤销能力。

## 实现前确认（进入本步骤时填写）

- [x] P3 已完成；online subscription、floating 和需要激活的 node_locked 使用在线能力，site/纯离线许可可不调用。
- [x] 当前仓库没有部署环境、数据库和身份供应商。本步骤先实现“可运行的内存参考服务 + HTTP API + 完整协议测试”，不得把它表述为生产持久化服务；数据库、TLS 终止、管理员认证和高可用部署继续保留为 P4 后续事项。
- [x] 参考策略：激活设备数来自服务端 entitlement；租约默认 5 分钟、时间票据 24 小时；在线不可用时客户端只能使用票据本身携带的已签名有效期，不能自行延长。
- [x] 主 License 与在线票据使用独立 Ed25519 KeyId 和域分离：`AUGENSTERN-LEASE-V1\0`、`AUGENSTERN-TIME-TICKET-V1\0`。

状态：实现前确认完成，开始 P4 参考服务实现。

## 详细实现事项

1. [x] 定义服务端 `OnlineEntitlement`，只允许受控注册流程写入 license_id、功能、激活数、并发数和 revocation_epoch；客户端请求不能上传 entitlement。
2. [x] Activation：installation_id、幂等 request_id、设备配额、重复激活返回同一记录、受控解绑。
3. [x] Lease：验证激活和功能子集，在单个互斥事务中清理过期租约并原子分配席位；幂等请求返回同一签名 token。
4. [x] Lease token：lease_id、license_id、installation_id、features、issued_at、expires_at、server_nonce、revocation_epoch。
5. [x] Time ticket：license_id、installation_id、server_time、valid_until、nonce、revocation_epoch。
6. [x] 对 Lease/TimeTicket 使用确定性 CBOR、独立域分离和在线服务 Ed25519 KeyId 签名。
7. [x] 客户端 verifier 只信任本地服务公钥，检查签名、类型、安装实例、有效期、撤销代际和 replay cache。
8. [x] Revocation：服务端拒绝新激活/租约/时间票据；客户端在已知更高 epoch 时拒绝旧票据。
9. [x] HTTP API：`/v1/activate`、`/v1/lease`、`/v1/time-ticket`，稳定 JSON 请求/响应和错误码；管理注册/撤销不暴露到公共路由。
10. [x] 审计：记录注册、激活、租约、解绑和撤销的最小化事件，不记录私钥或原始机器标识。
11. [x] 测试：激活配额、幂等、16 线程/请求并发不超发、崩溃式不释放依靠到期回收、错误功能、重放、过期、撤销和 HTTP 合约。
12. [x] CLI Demo：注册 entitlement → 激活 → 取租约/时间票据 → 客户端验证 → 撤销后拒绝。

## 验收标准

- 并发请求不会超发席位；客户端崩溃后租约可回收。
- 旧租约、旧时间票据和撤销前票据不可被无限重放。
- 在线服务不可用时严格按已签名宽限策略运行。
- 完全离线许可的撤销边界在产品和合同层明确。
- API 安全、并发、断网、时钟和灾难恢复测试通过。

参考实现完成标准与生产上线标准分开：内存服务可验证协议和原子状态机，但进程重启会丢失状态，因此不满足生产灾难恢复；P4 只有在持久化事务存储、管理员认证、TLS、备份恢复和监控完成后才能整体标记为完成。

## 预期文件

- `src/online/{mod,error,model,token,service,client,http}.rs`
- `src/bin/online_demo.rs`
- `tests/online_service.rs`、`tests/online_http.rs`

## 问题与新思路

### Git 报告 Windows 行尾转换提示

- 现象：最终 `git diff --check` 返回成功，但对仓库原有已跟踪文件提示“LF will be replaced by CRLF”。
- 影响：没有空白错误，也不影响 Rust 构建和测试；若批量格式化或改写文件，可能扩大与本步骤无关的差异。
- 新思路：不为本步骤批量转换用户原有文件行尾，只对新增/修改的 Rust 文件做定向 rustfmt；行尾规范可在后续发布加固时通过 `.gitattributes` 单独决策。
- 验证办法：以 `git diff --check` 退出码 0、完整测试和严格 Clippy 为本步骤证据。

### 初版租约分配无法在满席时正常续租

- 现象：初版按活动 token 数计数；当并发上限为 1 时，已持有租约的同一 `installation_id` 在租约到期前提交新 request_id 会收到 `LEASE_LIMIT`，同一安装也可能重复占用多个席位。
- 影响：心跳式续租会在满席时中断合法运行，并允许单一客户端无意中消耗多个浮动席位。
- 原因：租约记录以 `lease_id` 保存，但分配前没有先识别同一安装实例的现有活动租约。
- 新思路：把一个 `installation_id` 视为一个活动席位；同实例新请求是续租，在同一互斥事务中签发新票据并原子替换旧租约，不增加并发计数；不同实例仍严格受总配额约束。
- 验证办法：增加“并发上限为 1 时原实例可提前续租、另一实例仍被拒绝”的回归测试，并保留 16 线程争抢测试。

### 参考服务首次编译存在未使用导入告警

- 现象：`cargo check --lib` 成功，但 `src/online/service.rs` 的 `BTreeSet` 导入未被使用。
- 影响：不影响运行逻辑，但无法满足后续 `clippy -D warnings` 的零告警验收要求。
- 新思路：删除多余导入，不使用全局自动修复，避免改动无关代码。
- 验证办法：定向格式化在线模块，并在完整测试后执行严格 Clippy。

### 当前仓库没有生产服务基础设施

- 现象：没有数据库 schema、部署平台、域名/TLS、管理员身份系统、监控或备份设施。
- 影响：无法在本地代码仓库中诚实宣称已完成生产级在线 License 服务。
- 新思路：先把协议、安全边界、原子并发和 HTTP 合约实现为内存参考服务；所有状态操作集中在一个 service 接口，后续可用 SQLite/PostgreSQL 事务实现替换存储而不改变客户端 token。
- 验证办法：参考服务必须通过并发和协议测试；步骤状态保持“进行中”，直到持久化与运维项完成。

## 实现后同步

### 参考实现对照结果

| 需求 | 实际结果 | 同步状态 |
| --- | --- | --- |
| 受控 entitlement | `register_entitlement` 仅是进程内管理方法，三个公共 HTTP 请求均不接受功能或配额定义 | 一致 |
| 激活与解绑 | installation 级激活、幂等 request_id、设备配额、重复激活复用、管理侧 `deactivate` | 一致 |
| 浮动租约 | 同一 `Mutex<ServiceState>` 临界区内完成过期清理、同安装续租替换、配额判断、签名和写入；不同安装不会超发 | 一致（参考存储） |
| 票据 | `AOTK` v1 确定性 CBOR 信封；Lease/TimeTicket 字段与清单一致；Ed25519 签名分别使用两个域 | 一致 |
| 客户端 | 本地 KeyId + 公钥白名单验签，检查 token 类型、subject、时间范围、最低撤销代际及进程内 replay cache | 一致（持久化 cache 待后续） |
| 撤销 | 撤销递增 epoch、清除租约并拒绝新操作；客户端获知新 epoch 后拒绝旧票据 | 一致 |
| HTTP | POST `/v1/activate`、`/v1/lease`、`/v1/time-ticket`；业务错误和 JSON 拒绝均返回稳定 `code`；无公共管理路由 | 一致 |
| 审计 | 单调序号事件记录注册、激活/复用、租约签发/释放、解绑、撤销；不保存签名私钥或机器原始值 | 一致（内存） |

### API 与事务边界

- HTTP Router 位于 `src/online/http.rs`，仅暴露三个客户端端点；管理动作只存在于 service API。
- 参考服务的原子边界是 `ServiceState` 的单一互斥锁。幂等查询、授权检查、过期回收、席位判断和状态提交都在同一锁持有期内完成。
- 同一 installation 的新 lease 是续租并替换旧 lease，只计一个席位；不同 installation 的 16 路竞争不会超过 entitlement 配额。
- 该互斥锁不是数据库事务，也不能跨进程；后续存储适配必须用唯一约束和数据库事务保持相同语义。

### 票据与密钥

- 在线信封 magic 为 `AOTK`、版本 1，KeyId 最长 64 字符，payload 与 envelope 解码后重新编码以拒绝非规范 CBOR。
- Lease 默认有效 300 秒，TimeTicket 默认有效 86400 秒；本地时间早于签发时间、到达有效期、签名/类型/subject 错误均失败关闭。
- 在线服务 Ed25519 密钥与主 License 密钥逻辑独立；本地 server demo 的固定 `[42; 32]` 密钥已在输出和 README 标注为仅开发用途。

### 验证证据

- `cargo test --all-targets`：初次完整回归 49 项通过；修复续租语义后最终完整回归 50 项通过，其中在线专项 11 项（9 个 service + 2 个 HTTP）。
- `cargo clippy --all-targets -- -D warnings`：通过，零告警。
- `cargo run --bin online_demo`：成功完成激活、Lease/TimeTicket 客户端验签、撤销后拒绝，并产生 4 条最小审计事件。
- `cargo run --bin online_server -- 127.0.0.1:30391`：监听成功；真实 HTTP POST `/v1/activate` 返回 200 和预期 JSON，验证后服务已停止。

### 未完成与下一思路

- P4 参考协议与状态机已完成，但步骤整体保持“进行中”。内存 entitlement、幂等表、租约、审计和客户端 replay cache 在进程重启后丢失，尚无生产灾难恢复能力。
- 下一子步骤应建立持久化存储接口与 SQLite/PostgreSQL 事务实现，定义 request_id 唯一约束、installation/lease 索引和审计保留策略；随后增加管理员认证、TLS/反向代理边界、限流、密钥托管、指标告警和备份恢复演练。
- 完全离线 License 无法实时撤销；该能力边界保持为产品策略与合同约束，不由在线参考服务虚假覆盖。

状态：P4 在线参考实现已完成并同步；生产持久化与运维子步骤未完成，因此 P4 仍为“进行中”。
