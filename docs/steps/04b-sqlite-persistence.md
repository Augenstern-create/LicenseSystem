# P4.2：在线服务 SQLite 持久化事务存储

## 目标

把 P4.1 已验证的在线协议状态机迁移到可重启恢复的 SQLite 参考存储，并保持 HTTP 合约、票据格式和客户端信任根不变。此步骤解决单节点持久化与原子事务，不宣称已完成管理员认证、TLS、高可用或异地灾备。

## 实现前确认

- [x] P4.1 内存参考服务、HTTP API、票据格式和 50 项全量测试已通过。
- [x] 数据库不得保存在线 Ed25519 私钥；私钥仍由进程构造参数注入，后续迁移到 KMS/HSM。
- [x] 采用 `rusqlite 0.40.1` 的 bundled SQLite，避免依赖目标机器预装 SQLite 动态库。
- [x] SQLite 面向单节点参考部署；写事务使用 `BEGIN IMMEDIATE`，并通过数据库唯一约束防止多连接超发。
- [x] 公共 HTTP 路由继续只暴露 activate、lease、time-ticket；持久化不会扩大管理接口权限。
- [x] P4.1 的内存实现保留用于快速单元测试；HTTP Router 抽象为可接受内存或 SQLite 后端。

状态：实现前确认完成，开始 P4.2。

## 数据库模型

1. `entitlements`：license_id 主键、规范 JSON 功能集、激活上限、并发上限、revocation_epoch、revoked。
2. `activations`：`(license_id, installation_id)` 主键，activation_id 唯一，记录 activated_at。
3. `leases`：lease_id 主键，`(license_id, installation_id)` 唯一，只允许每个安装持有一个活动席位，记录 expires_at。
4. `idempotency`：`(operation, request_id)` 主键，保存原请求 JSON 和原响应 JSON；同 request_id 不同内容失败关闭。
5. `audit_events`：数据库自增序号、动作、license_id、可选 installation_id、actor、reason、occurred_at。
6. `PRAGMA user_version` 管理 schema 版本；未知的更高版本必须拒绝打开，迁移必须在事务中执行。

## 详细实现事项

1. [x] 引入 bundled `rusqlite`，新增 `SqliteOnlineLicenseService`，初始化 foreign_keys、busy timeout、WAL 和 schema migration。
2. [x] 把 entitlement 注册和最小审计写入同一 `BEGIN IMMEDIATE` 事务。
3. [x] 持久化 Activation：幂等查询、撤销检查、设备配额、重复安装复用、响应与审计原子提交。
4. [x] 持久化 Lease：幂等查询、授权/功能检查、过期清理、同安装续租替换、并发计数、token 与状态原子提交。
5. [x] 持久化 TimeTicket 幂等响应，重启后相同 request_id 返回完全相同 token。
6. [x] 持久化 release、deactivate、revoke 和审计；撤销递增 epoch 并在同一事务清除活动租约。
7. [x] 抽象 HTTP service 接口，使内存和 SQLite 后端共用完全相同的公共 Router 与错误映射。
8. [x] 新增 SQLite server demo，数据库路径通过命令行传入，禁止静默覆盖或把开发私钥描述为生产密钥。
9. [x] 测试重启恢复 entitlement/activation/idempotency/lease/撤销/审计。
10. [x] 测试两个独立 SQLite service 连接并发争抢，确保数据库事务不会超发。
11. [x] 测试 schema 版本拒绝、外键、唯一约束和过期租约回收。
12. [x] 运行全量测试、严格 Clippy、diff check，并同步 README 与步骤结果。

## 事务与失败策略

- 所有会影响授权结果的读写都在 `TransactionBehavior::Immediate` 事务内完成；不得先读配额、提交锁后再写租约。
- token 必须在事务提交前生成并与幂等响应一起保存。签名或序列化失败时事务回滚，不消耗席位。
- SQLite busy、I/O、损坏、schema 不兼容、JSON/UUID 数据损坏统一失败关闭为内部错误；公共响应不得暴露 SQL 文本或文件路径。
- 时间仍由服务调用方注入，HTTP 使用 UTC；数据库只保存服务已作出的决定，不信任客户端时间。
- SQLite 文件本身不保存机器原始标识，只保存随机 installation UUID；数据库文件权限、磁盘加密和备份加密属于后续部署加固。

## 验收标准

- 进程/连接关闭并重新打开后，相同幂等请求返回字节完全相同的响应。
- 激活、租约、撤销和审计在重启后保持；过期租约可回收。
- 两个独立连接的并发租约分配不超过 entitlement 上限。
- HTTP 合约对内存与 SQLite 后端一致。
- `cargo test --all-targets`、`cargo clippy --all-targets -- -D warnings`、`git diff --check` 全部通过。

## 预期文件

- `src/online/sqlite.rs`
- `src/online/http.rs`、`src/online/mod.rs`
- `src/bin/online_sqlite_server.rs`
- `tests/online_sqlite.rs`、`tests/online_http.rs`
- `Cargo.toml`、`Cargo.lock`、`README.md`

## 问题与新思路

### 重启误配签名密钥会让持久化幂等 token 与当前公钥不一致

- 现象：初版数据库持久化了已签名响应，但没有记录生成这些 token 的签名身份；若重启时传入同 KeyId、不同私钥，相同 request_id 会返回旧 token，而服务当前公开的 verifying key 已改变。
- 影响：合法幂等响应在客户端验签时失败，新旧 token 也会混用两个信任根。
- 新思路：schema 增加单例 `service_identity`，只保存 KeyId 和 Ed25519 公钥字节，不保存私钥；首次打开写入，后续打开必须与注入私钥导出的公钥完全一致，否则失败关闭。
- 验证办法：同数据库同密钥可重启，不同密钥或不同 KeyId 打开均被拒绝。

### SQLite Demo 初稿尝试用错误码文本判断已有 entitlement

- 现象：Demo 的重启分支初稿对 `OnlineErrorCode` 调用字符串转换，但错误码没有也不应依赖展示文本实现。
- 影响：代码无法编译，且文本比较会让控制流依赖不稳定的错误文案。
- 新思路：直接导入并比较强类型 `OnlineErrorCode::InvalidRequest`；仅在用户显式传入已有 license_id 且固定 demo entitlement 已通过本地字段校验时复用。
- 验证办法：编译所有 target，并实际使用同一数据库和 license_id 连续启动两次。

### 协议 u64 撤销代际超出 SQLite INTEGER 正数范围

- 现象：`revocation_epoch` 的 Rust/票据类型为 `u64`，SQLite INTEGER 只能精确保存 `i64`。
- 影响：若直接强制转换，超过 `i64::MAX` 的值可能截断或变为负数，破坏撤销顺序。
- 新思路：SQLite 注册入口拒绝大于 `i64::MAX` 的 epoch；撤销在达到上限时失败关闭，不做饱和或回绕。现实业务不可能正常消耗该数量级，但存储边界必须显式。
- 验证办法：增加超范围 entitlement 被拒绝的测试，并使用受检转换读取数据库值。

后续发现问题时，继续在本节先记录现象、影响、原因、方案和验证办法，再修改代码。

## 实现后同步

### 实现结果对照

| 需求 | 实际结果 | 状态 |
| --- | --- | --- |
| SQLite 初始化 | bundled SQLite、5 秒 busy timeout、foreign_keys、WAL、`user_version=1` | 一致 |
| schema | `service_identity`、`entitlements`、`activations`、`leases`、`idempotency`、`audit_events` 和 expiry index | 一致；比初始清单增加公开签名身份绑定 |
| 原子事务 | 所有授权读写使用 `TransactionBehavior::Immediate`，token/幂等/状态/审计提交失败时整体回滚 | 一致 |
| 激活与幂等 | 重启后同 request_id 返回同 activation；不同请求内容失败关闭 | 一致 |
| Lease | 外键保证已激活，唯一约束保证每 installation 一个席位；过期清理、续租替换和并发计数同事务 | 一致 |
| TimeTicket | 完整 token JSON 存入幂等表，重启后字节不变 | 一致 |
| 撤销与审计 | epoch 受检递增、清空租约、审计自增序号均持久化 | 一致 |
| HTTP | `OnlineHttpService` 让内存与 SQLite 共用三个公共端点和错误映射 | 一致 |

### Schema 与迁移

- schema 版本为 1；新库在 immediate 事务内建表并设置 `PRAGMA user_version=1`。
- 打开高于当前版本的数据库会失败关闭，不尝试向下解释未知 schema。
- `service_identity` 只保存 KeyId 和 32 字节 Ed25519 公钥。数据库不保存私钥；同库使用不同 KeyId 或公钥重启会被拒绝。
- `activations` 以 `(license_id, installation_id)` 为主键；`leases` 对同一组合设置唯一约束并以复合外键引用 activation。
- `idempotency` 以 `(operation, request_id)` 为主键，保持与 P4.1 各操作独立幂等命名空间一致。

### 事务边界

- entitlement 与注册审计同事务。
- Activation 的幂等检查、撤销/配额读取、activation 写入、响应保存和审计同事务。
- Lease 的幂等检查、激活/功能验证、过期删除、席位计数、签名、旧租约替换、响应保存和审计同事务。
- TimeTicket 的授权检查、签名和幂等响应同事务。
- release/deactivate/revoke 的状态变化和审计同事务；revoke 同时递增 epoch 并删除租约。

### 验证证据

- SQLite 专项 7 项通过：重启恢复、token/activation 幂等、撤销/审计恢复、两个独立连接并发、过期回收、schema/epoch 边界、签名身份、外键/唯一约束和共用 HTTP Router。
- 两个独立 service 连接、16 个线程争抢并发上限 2，严格只有 2 个请求成功。
- 实际启动 `online_sqlite_server`，完成 HTTP 激活后停止；使用同一数据库和 license_id 重启显示 `entitlement=existing`，相同 request_id 返回完全相同 activation_id 与 activated_at。
- `cargo test --all-targets`：57 项全部通过，无失败或忽略。
- `cargo clippy --all-targets -- -D warnings`：通过，零告警。
- `git diff --check`：退出码 0；仅保留已在 P4.1 记录的 Windows LF/CRLF 提示，不批量改写用户原有文件。

### 偏差与后续

- SQLite 是单节点事务存储，不提供多节点共识、自动故障转移或跨区域灾备。
- idempotency 与审计当前永久保留，尚未实现合规保留/归档/清理任务；清理不能早于 token 和客户端重试窗口。
- 数据库文件权限、磁盘/备份加密、管理员认证、TLS、限流、指标、告警和恢复演练属于 P4.3。
- 客户端 replay cache 仍是进程内状态；在产品集成中应与 P3 的受保护本地状态统一持久化。

状态：P4.2 SQLite 持久化实现与同步完成；P4.3 生产安全和运维能力未开始。
