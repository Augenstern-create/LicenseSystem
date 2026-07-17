# P6：代码注释、架构、接口与开发者交付文档

## 目标

把 P0～P5 已实现的 License 系统整理为可阅读、可编译、可测试、可集成和可继续开发的工程交付物。文档必须以当前代码为准，不把外部生产依赖描述为已完成。

## 实现前确认

- [x] P0～P5 仓库内实现已经完成，全量基线为 69 项测试通过。
- [x] 本步骤只补充注释、文档、示例导航和必要的文档测试，不改变 License/在线票据协议字节格式。
- [x] Rust 公共 API 使用 `///` rustdoc；关键私有安全函数使用简短 `//` 注释解释不明显的边界和失败策略。
- [x] 文档主体使用 Markdown，统一放入 `docs/`；README 作为入口，不重复粘贴全部设计内容。
- [x] 接口文档必须覆盖离线库 API、虚拟 SDK、机器身份、时间锚、在线公共 HTTP API、管理 API、CLI 和稳定错误码。
- [x] 编译文档同时说明普通开发、release、安全 Server、Python 向量验证、fuzz target 和 Windows 环境注意事项。
- [x] 测试文档必须说明测试文件、测试函数用途、单项运行命令和临时文件位置。
- [x] 后续事项必须区分代码待办、外部基础设施、组织治理和正式发布阻塞项。

状态：实现前确认完成，开始 P6。

## 详细实现事项

1. [x] 盘点所有 `pub` 模块、类型、trait、函数和 CLI，建立文档覆盖表。
2. [x] 为 crate、模块、公共类型、公共字段、构造函数、查询函数和安全关键方法补齐 rustdoc。
3. [x] 为 CBOR 规范性复核、签名域分离、机器归一化、时间锚原子替换、SQLite immediate 事务、重放缓存和认证比较增加必要内部注释。
4. [x] 编写 `docs/ARCHITECTURE.md`：信任边界、模块关系、离线/在线流程、数据存储和部署拓扑。
5. [x] 编写 `docs/API.md`：Rust API、HTTP API、管理 API、CLI、错误码和调用示例。
6. [x] 编写 `docs/BUILD_AND_TEST.md`：环境、依赖、debug/release 编译、rustdoc、测试文件/函数、专项命令、fuzz 和 Python 验证。
7. [x] 编写 `docs/ROADMAP.md`：已完成能力、当前限制、后续代码事项、生产治理和发布准入。
8. [x] 更新 README：项目定位、快速开始、模块清单、编译步骤、Demo、测试使用和文档导航。
9. [x] 增加文档链接检查，拒绝 README/docs 中不存在的本地 Markdown 链接。
10. [x] 执行 `cargo doc --no-deps`、全量测试、严格 Clippy、Python 向量和 diff check。

## 验收标准

- 新开发者只阅读 README 和三份核心文档即可完成编译、运行 Demo、启动在线服务和执行测试。
- 公共 API 的 rustdoc 不再依赖阅读实现才能理解参数、返回值和安全边界。
- 架构图与实际模块、路由、SQLite schema、KeyId/domain separator 保持一致。
- 测试文档能定位每个测试文件及主要测试函数的验证目标。
- 后续事项明确列出当前正式发布阻塞项和责任归属，不把参考实现写成生产完成。
- 文档链接检查、rustdoc、69+ 项测试和严格 Clippy 通过。

## 预期文件

- `docs/ARCHITECTURE.md`
- `docs/API.md`
- `docs/BUILD_AND_TEST.md`
- `docs/ROADMAP.md`
- `docs/steps/06-documentation-and-handoff.md`
- `scripts/check_markdown_links.ps1`
- `README.md`
- `src/**/*.rs` 的 rustdoc/关键注释

## 问题与新思路

### 首次严格 rustdoc 显示公共 API 注释缺口广泛

- 现象：`RUSTDOCFLAGS="-D missing-docs" cargo doc --no-deps --lib` 失败，报告模块、类型、枚举成员、公共字段和方法缺少文档，输出超过 2000 行并被截断。
- 影响：普通 rustdoc 可生成页面，但公共 API 无法达到严格注释验收，不能只补少数入口函数。
- 新思路：按 `license → machine/time_anchor → online → demo_sdk` 的依赖顺序分批补齐，每批运行严格 rustdoc 收敛。
- 验证办法：最终同一严格命令退出 0，不使用 crate 级 `allow(missing_docs)` 绕过。

### 第一批大范围注释补丁上下文不匹配

- 现象：组合补丁假设 `ErrorCode` derive 后直接进入枚举，但实际存在 `#[non_exhaustive]`，补丁校验失败且未应用任何文件。
- 影响：没有产生半完成注释；大补丁的任一上下文偏差会阻断全部文件。
- 新思路：按文件拆分注释补丁，先读取公开段落；每批完成后定向 rustfmt 并运行严格 rustdoc。
- 验证办法：各批次独立应用和验证，失败不影响其他模块。

### governance 模块注释被插入文件末尾

- 现象：缺少明确顶部上下文的补丁把 `//! Policy-enforced...` 放到 `governance.rs` 第 185 行文件末尾，rustfmt/rustdoc 报 `expected outer doc comment`。
- 影响：该模块暂时无法解析，测试尚未运行；业务语句没有改变。
- 新思路：删除末尾注释并在首个 `use` 前显式插入模块级文档；后续模块注释都使用文件首行上下文。
- 验证办法：定向 rustfmt 成功，严格 rustdoc 能继续报告下一批 missing-docs。

后续遇到文档与实现不一致、rustdoc、链接或测试问题时，继续先记录现象、影响、方案和验证方法，再修改。

## 实现后同步

### 交付文档

| 文档 | 内容 | 状态 |
| --- | --- | --- |
| `README.md` | 项目入口、模块、编译、Demo、测试、发布限制和导航 | 完成 |
| `docs/ARCHITECTURE.md` | 组件图、信任边界、离线/在线流程、schema、部署拓扑和安全不变量 | 完成 |
| `docs/API.md` | Rust API、Payload、SDK、机器/时间、公共/管理 HTTP、错误码和 CLI | 完成 |
| `docs/BUILD_AND_TEST.md` | 环境、debug/release、rustdoc、Demo、69 项测试函数、fuzz 和故障排查 | 完成 |
| `docs/ROADMAP.md` | 已完成阶段、代码后续、生产治理、责任矩阵和发布准入 | 完成 |
| `scripts/check_markdown_links.ps1` | README/docs/release 本地文件和 Markdown anchor 检查 | 完成 |

### 代码注释覆盖

- crate 根和 `license`、`machine`、`time_anchor`、`online`、`demo_sdk` 公共模块均有模块级 rustdoc。
- 公共枚举、成员、结构体、公共字段、trait 方法、构造函数、查询方法、Router 和服务方法均通过 `missing_docs` 严格检查。
- 关键内部逻辑补充了规范 CBOR 重新编码、哈希长度前缀、重放判定、管理员 token 常量时间比较、内存事务边界和 SQLite immediate 写锁说明。
- 没有使用 `allow(missing_docs)` 绕过公共 API 文档要求。

### 验证证据

- `RUSTDOCFLAGS="-D missing-docs -D rustdoc::broken-intra-doc-links" cargo doc --no-deps --lib`：通过。
- `cargo test --all-targets`：69 项全部通过。
- `cargo clippy --all-targets -- -D warnings`：通过。
- `scripts/verify_license_vector.py`：Python 独立验证通过。
- `scripts/check_markdown_links.ps1`：22 个 Markdown 文件、27 个本地链接、0 个失败。
- `release_secret_audit.ps1 -AuditOnly`：扫描 117 个候选文件，只报告已知 `keys/rsa_private.der` blocker。
- `git diff --check`：通过；Windows 行尾提示保持既有处理策略。

### 偏差和维护责任

- 本步骤没有改变协议、schema、HTTP 路由或测试逻辑，仅增加文档和注释。
- rustdoc 只验证 library 公共 API；CLI 的参数和安全边界统一记录在 README/API/BUILD 文档中。
- 架构、接口或命令发生变更时，代码提交者必须同步更新对应文档和链接检查。
- 生产发布仍受 P5 外部事项阻塞，文档完成不改变该发布结论。

状态：P6 完成。
