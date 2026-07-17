# P4.3：在线服务安全入口与运维能力

## 目标

在 P4.2 单节点 SQLite 事务服务上增加可验证的管理面认证、TLS 启动方式、请求防护、运行指标、在线备份和恢复演练。真实证书签发、外部身份系统、集中监控和跨节点高可用需要部署环境，本步骤只提供安全参考实现与明确接口。

## 实现前确认

- [x] P4.1 在线协议与 P4.2 SQLite 持久化已完成，全量 57 项测试通过。
- [x] 管理 API 与客户端 API 是不同信任面；管理操作必须认证，actor 从服务端凭据映射得出，不能信任请求体自报身份。
- [x] 管理凭据不写入数据库、源码、命令行或日志；安全 Server 从环境变量读取，存储时只保留 SHA-256 hash，并做常量时间比较。
- [x] TLS 使用 `axum-server 0.8.0` + rustls，从外部 PEM 证书/私钥文件加载；仓库不生成或提交生产证书。
- [x] 在线签名私钥由外部文件注入，安全 Server 禁止固定开发私钥；P4.2 数据库继续校验 KeyId 与公钥一致性。
- [x] 进程内限流只能作为最后一道保护，生产还需要反向代理/WAF 的按来源限流和 DDoS 防护。
- [x] SQLite 在线备份使用 SQLite backup API，不复制活动 WAL 文件；恢复必须重新执行完整性、schema 和签名身份检查。

状态：实现前确认完成，开始 P4.3。

## 详细实现事项

1. [x] 新增管理凭据模型：credential_id + token hash、常量时间校验、Bearer 解析、禁用空值/控制字符。
2. [x] 新增独立管理 Router：注册 entitlement、撤销、解绑、审计查询、指标和触发备份。
3. [x] actor 只能来自认证 credential_id；公共 Router 继续不包含管理端点。
4. [x] 新增全局固定窗口限流、并发中计数、2xx/4xx/5xx 请求计数和稳定 429 JSON 错误。
5. [x] 对公共与管理请求设置明确 body size 上限；异常 JSON 继续使用稳定错误码。
6. [x] 为 SQLite 服务增加在线 backup API、`PRAGMA integrity_check` 和恢复打开验证。
7. [x] 备份路径只能由服务端配置目录和服务端生成文件名决定，管理请求不能提交任意文件路径。
8. [x] 新增 TLS Server：外部数据库、KeyId、32 字节 Ed25519 私钥、证书和证书私钥；管理员 token 仅从环境读取。
9. [x] 测试无凭据/错误凭据拒绝、正确 actor 审计、管理路由不进入公共 Router。
10. [x] 测试限流 429、指标计数、body 上限和敏感 token 不出现在响应/审计中。
11. [x] 测试在线备份可恢复 entitlement、激活、幂等 token、撤销代际和审计，损坏备份失败关闭。
12. [x] 使用测试证书实际启动 TLS 服务并完成 HTTPS 请求；证书只放在忽略的 `target/`。
13. [x] 编写部署/备份/恢复/监控 Runbook，记录告警阈值和仍需外部平台完成的事项。
14. [x] 全量测试、严格 Clippy、diff check，通过后同步文档并进入 P5。

## API 与安全策略

- 公共端点保持 `/v1/activate`、`/v1/lease`、`/v1/time-ticket`。
- 管理端点使用 `/admin/v1/...`，每次请求要求 `Authorization: Bearer <secret>`；认证失败只返回统一 401，不区分 credential 是否存在。
- 管理 token 最低 32 字节；参考实现支持单凭据，生产可替换为 mTLS/OIDC 并保持 actor 映射接口。
- body 默认最大 64 KiB；超过限制返回 413。全局限流超过阈值返回 `RATE_LIMITED`/429，不进入业务状态机。
- 指标只记录计数，不记录 token、License 完整值、installation 原始值、请求体或私钥。
- 备份文件名由 UTC 时间戳和随机 UUID 生成；备份目录启动时配置，API 请求不能越界选择路径。

## 验收标准

- 未认证用户无法注册、撤销、解绑、读取审计/指标或触发备份。
- 管理审计 actor 来自认证上下文，token 不进入日志、响应或数据库。
- TLS Server 缺少 token、证书、私钥或签名密钥时拒绝启动。
- 限流、body 上限和指标测试通过；公共协议兼容 P4.1/P4.2。
- 在线备份通过完整性检查并可恢复关键状态；损坏文件失败关闭。
- 全量质量命令通过。

## 预期文件

- `src/online/{admin,operations}.rs`
- `src/online/sqlite.rs`、`src/online/http.rs`、`src/online/model.rs`
- `src/bin/online_secure_server.rs`
- `tests/online_admin.rs`、`tests/online_backup.rs`
- `docs/runbooks/online-operations.md`
- `Cargo.toml`、`Cargo.lock`、`README.md`

## 问题与新思路

### Windows TLS Server 首次链接出现 linker_messages 提示

- 现象：`cargo run --bin online_secure_server` 成功，但 MSVC 链接器在创建 `.lib/.exp` 时输出本地化提示，rustc 以 `linker_messages` warning 展示。
- 影响：服务正常启动，HTTPS 验证通过；该提示不是 Rust/Clippy 代码告警。
- 新思路：不在项目中全局禁用 linker messages，避免掩盖未来真正的链接器警告；以严格 Clippy、退出码和实际 TLS 请求作为质量证据。
- 验证办法：`cargo clippy --all-targets -- -D warnings` 必须通过，TLS 进程必须同时监听并完成 401/201/200 请求链路。

### 管理/备份模块首次编译出现公开 API 与名称遮蔽问题

- 现象：rusqlite 0.40.1 的 backup 示例接受公开 `MAIN_DB` 常量，根模块不导出 `DatabaseName` 类型；同时 `admin_router` 的 `metrics` 参数遮蔽了同名 handler，Axum 把指标对象误当作 Handler。
- 影响：`cargo check --lib` 出现 2 个编译错误，尚未进入运行阶段。
- 新思路：使用 rusqlite 官方公开的 `MAIN_DB`；把参数改为 `operational_metrics`、handler 改为 `get_metrics`，消除名称解析歧义。
- 验证办法：定向 rustfmt 后重新执行 `cargo check --lib`。

补充：首次重命名补丁只命中了 `AdminState` 字段，未同步函数参数和读取点，第二次编译暴露 3 个一致性错误；按实际行统一字段、参数和 handler 读取点后再次验证。

### 首次依赖补丁上下文与 Cargo.toml 当前顺序不一致

- 现象：一次组合补丁在定位 `sha2` 段落时校验失败，补丁工具未应用任何部分。
- 影响：没有代码或依赖处于半修改状态，仅延迟实现。
- 新思路：读取当前依赖段并按实际相邻行分别添加 `axum-server`、`subtle` 和 rusqlite backup feature，避免依赖字段顺序假设。
- 验证办法：随后执行 `cargo check --lib` 并检查 lockfile 解析。

后续问题继续先记录问题、影响、原因、方案和验证办法，再调整代码。

## 实现后同步

### 对照结果

| 需求 | 实际结果 | 状态 |
| --- | --- | --- |
| 管理认证 | 高熵 Bearer token 仅保存 SHA-256 hash，`subtle` 常量时间比较；actor 固定映射 credential_id | 一致 |
| 管理面隔离 | 独立 loopback TLS listener 和 `/admin/v1/*` Router；公共 Router 对管理路径返回 404 | 一致 |
| 请求防护 | 64 KiB body 上限、全局固定窗口限流、稳定 401/413/429 JSON 错误 | 一致；按来源限流依赖 WAF |
| 指标 | total、in-flight、2xx/4xx/5xx、rate-limited 原子计数 | 一致；进程重启归零 |
| TLS | rustls 从外部 PEM 加载；外部 32 字节 Ed25519 私钥；管理地址强制 loopback | 一致 |
| 在线备份 | SQLite backup API、拒绝覆盖、integrity_check、schema 与签名身份校验 | 一致 |
| Runbook | 启动、TLS、指标阈值、备份、恢复和事件处置 | 一致 |

### 验证证据

- 管理/运维专项 6 项通过：认证、actor、路由隔离、限流、指标、body 上限、服务端备份路径、恢复幂等和损坏失败关闭。
- 使用 `target/secure-demo` 一次性密钥和自签证书启动双 TLS listener；未认证管理请求 401、认证注册 201、公共激活 200。
- 实际管理备份成功，并返回服务端生成的无路径文件名；指标返回请求分类计数且不含敏感标识。
- `online_backup_verify` 使用公钥验证备份完整性、schema 和签名身份。
- `cargo test --all-targets`：63 项全部通过。
- `cargo clippy --all-targets -- -D warnings`：通过，零 Clippy 告警。
- `git diff --check`：退出码 0；Windows 行尾提示沿用已记录决策。

### 仍需部署环境完成

- 当前认证是单高熵 token，生产应迁移到短期 OIDC/mTLS、权限分级和无停机轮换。
- 进程内限流是全局窗口，不替代 WAF/反向代理按来源限流、超时和 DDoS 防护。
- 指标未直接导出 Prometheus/OpenTelemetry，需外部采集持久化与告警平台。
- 已提供在线备份和恢复流程，但自动调度、不可变异地存储和正式 RPO/RTO 演练需要真实基础设施与责任人。
- SQLite 仍是单节点，不提供多节点高可用或跨区域共识。

状态：P4.3 仓库内可实现的安全与运维参考能力已完成；外部生产平台事项明确记录，进入 P5。
