# P1：离线核心闭环

## 目标

实现可以独立签发、严格验证并向业务提供只读授权能力的 Rust 核心库和命令行工具。

## 实现前确认

- P0 信封、Payload、域分离、CBOR 规范性和模块边界已冻结。
- 本步骤只接受外部机器匹配结果，不采集硬件；不实现在线激活、撤销查询或时间锚。
- 现有 ECDSA/RSA/AES 文件保留为算法演示，不作为新核心库入口。
- 私钥仅由签发 CLI 读取，验证库类型只接收 `VerifyingKey`。
- 状态：已确认，已实现并通过验收。

## 详细实现事项

### A. 数据模型与边界

- [x] 建立 `LicensePayload`、`MachinePolicy`、`LicenseType`。
- [x] JSON 时间使用 RFC 3339，内部 CBOR 使用 Unix 秒。
- [x] 对 JSON 使用 `deny_unknown_fields`。
- [x] 建立长度/数量上限：短文本 256 字节、KeyId 64 字节、Map 256 项、资源值 1024 项、指纹 16 项。
- [x] 明确并测试 LicenseType 与 machine_policy 的组合约束：node_locked 必须提供策略。

### B. 确定性 CBOR

- [x] 使用固定整数键编码 18 个 Payload 字段和 6 个信封字段。
- [x] 拒绝不定长集合、重复动态键、未知/乱序字段和尾随数据。
- [x] 动态 Map 使用编码键规范排序。
- [x] 解码后重编码比较。
- [x] 增加独立的固定十六进制和 SHA-256 测试向量，供未来跨语言实现使用。

### C. 签发与验证

- [x] Ed25519 对域分离前缀和 payload 签名。
- [x] KeyRing 按 KeyId 查找内置公钥并执行状态检查。
- [x] 严格验证签名后再解析 payload。
- [x] 校验 schema、产品、有效期、SemVer、维护期和机器匹配结果。
- [x] 形成严格策略：`now < not_before.unwrap_or(issued_at)` 时拒绝，不在 P1 自动放宽未来签发时间。

### D. AuthorizationContext

- [x] 字段私有，只能通过只读方法访问。
- [x] 提供 `has_feature`、`get_limit`、`get_resource_scope`。
- [x] 增加 `require_feature`，未授权时返回 `LIC_FEATURE_DENIED`。

### E. CLI 和示例

- [x] `license_keygen`：生成 32 字节 Ed25519 私钥/公钥，拒绝覆盖。
- [x] `license_issue`：严格读取 JSON 和私钥并输出 `.lic`，拒绝覆盖。
- [x] `license_verify`：使用公钥、KeyId 和产品 ID 验证。
- [x] 增加 `licenses/payload.example.json`。
- [x] 为 README 增加完整命令示例和生产密钥警告。

### F. 测试与质量门

- [x] 合法 License 与 AuthorizationContext 查询。
- [x] 确定性重复签发。
- [x] 单字节篡改、未知算法、未知/撤销 KeyId。
- [x] 过期、产品不匹配、机器阈值、文件超限和尾随数据。
- [x] 尚未生效、版本上下限、维护期、无机器匹配结果、字段/集合边界。
- [x] `cargo test --all-targets`。
- [x] `cargo clippy --all-targets -- -D warnings`。
- [x] CLI 端到端生成、签发、验证演练。
- [x] `git diff --check` 和敏感文件检查；确认历史 `keys/rsa_private.der` 仍被跟踪并只能作为泄漏测试密钥。

## 验收标准

1. 所有质量门通过且没有 warning。
2. 客户端库没有编译或读取私钥的代码路径。
3. 测试证明篡改、错误信任根、错误业务条件均失败关闭。
4. 示例 CLI 能从 JSON 生成二进制 License 并成功验证。
5. 实现后同步表完整记录文件、测试和所有偏差。

## 问题与新思路

### Cargo 命令不在 PowerShell PATH

- 现象：直接运行 `cargo` 报“无法识别”。
- 影响：无法执行基线测试和后续质量门。
- 原因：Rust 工具位于 `%USERPROFILE%\.cargo\bin`，未加入当前会话 PATH。
- 新思路：步骤命令统一使用绝对路径 `%USERPROFILE%\.cargo\bin\cargo.exe`。
- 验证：基线 `cargo test --all-targets` 已运行成功（只有历史代码 warning）。

### 首次新增模块的私有类型导入失败

- 现象：`cbor.rs`、`signing.rs` 从父模块导入 `LicenseEnvelope`，但该内部类型未在父模块 re-export。
- 影响：`cargo check --lib` 失败，错误 E0432。
- 原因：把公开 re-export 与 crate 内部模块可见性混为一处。
- 新思路：不公开信封内部结构，两个模块直接使用 `model::LicenseEnvelope`。
- 验证：修正后 `cargo check --lib` 通过。

### 历史私钥已被 Git 跟踪

- 现象：`keys/rsa_private.der` 在仓库中，原 `.gitignore` 只忽略 `*.key`。
- 影响：该 RSA 密钥应视为泄漏，不能用于生产；简单新增 ignore 不能删除历史。
- 新思路：本步骤扩充私钥忽略规则但不擅自删除用户文件；P5 执行密钥轮换和历史清理方案。
- 验证：P1 最终敏感文件检查需列出所有已跟踪私钥并形成结论。

### 首轮全目标测试通过但历史代码 warning 阻塞质量门

- 现象：新增核心库 10 个测试全部通过，但 `aes.rs`、旧 `generate_key.rs` 和 `rsa.rs` 出现未使用导入、弃用 API、未使用常量 warning。
- 影响：P1 要求 `clippy -D warnings`，因此不能把“测试通过”视为步骤完成。
- 原因：warning 来自 P1 之前的算法演示，新增依赖/编译全部 target 后一起暴露。
- 新思路：只做不改变历史演示行为的局部清理：移除未使用 trait/常量，把弃用的切片 API 改为当前数组/TryFrom API；随后重跑所有 target。
- 验证办法：`cargo test --all-targets` 和 `cargo clippy --all-targets -- -D warnings` 都无 warning。

### 跨语言测试向量不能只依赖运行时“重复签发一致”

- 现象：当前测试能证明同一 Rust 实现重复签发一致，但不能让未来 C#/Java/C++ 实现核对固定字节。
- 影响：尚未满足方案中的跨平台编码一致性验收。
- 新思路：使用固定测试私钥和固定 Payload，记录完整 License 十六进制及 SHA-256；测试直接比较固定十六进制。测试私钥必须明确标注为公开测试材料，绝不可生产使用。
- 验证办法：Rust 测试固定比较通过；后续语言以同一向量验证 payload、签名和信封字节。

### Clippy 严格模式发现两处非功能性阻塞

- 现象：13 个测试全部通过、编译无 warning，但 `clippy -D warnings` 报 `needless_lifetimes` 和 `collapsible_if`。
- 影响：不影响运行结果，但 P1 硬性质量门仍未通过。
- 原因：`canonical_keys` 显式生命周期可由编译器推断；维护期判断使用了可合并的两层 `if`。
- 新思路：按 Clippy 建议省略生命周期，并用带 guard 的 `if let` 合并条件，不添加 `allow` 绕过规则。
- 验证办法：重新运行完整测试和严格 Clippy，必须零错误零 warning。
- 二次检查：前两项修复后，Clippy 又在历史 `generate_key.rs` 发现 `fs::write` 的多余借用；采用所有权传参不会改变行为，修正后再次运行完整质量门。

### 最终安全对照发现三个失败关闭差距

- 现象 1：字段数量上限允许构造超过 64 KiB 的合法模型，签发端会输出文件，客户端随后因文件上限拒绝。
- 影响：Issuer 可能生成自己客户端无法使用的 License。
- 新思路：`issue_license` 在信封编码完成后再次检查最终字节数，超限立即 `LIC_FORMAT_INVALID`。
- 现象 2：CBOR 解码器会按声明的数组长度调用 `Vec::with_capacity`；即使输入文件很小，恶意长度也可能请求过量内存。
- 影响：违反有界解析目标，存在拒绝服务风险。
- 新思路：在任何动态 Map/Array 进入循环或预分配前设置解码硬上限；模型层继续使用更严格的业务上限。
- 现象 3：KeyRing 使用 `insert` 后才判断重复，报错时旧公钥已被新值替换。
- 影响：调用者若忽略插入错误，信任状态已经发生意外变化。
- 新思路：先用 `contains_key` 检查，只有不重复时才插入，并增加回归测试证明原键仍可验证。
- 验证办法：分别增加超大签发、恶意集合长度和重复 KeyId 保留旧键的测试，再跑完整质量门。

### CLI 首次端到端演练被示例签发时间阻断

- 现象：`license_keygen`、`license_issue` 成功，`license_verify` 返回 `LIC_NOT_YET_VALID`。
- 影响：README 中的演练命令不能在当前运行时直接完成闭环。
- 原因：示例 Payload 使用方案日期 `2026-07-15`，但进程读取到的操作系统 UTC 早于该时间；对话环境日期与底层系统时钟并非同一来源。
- 新思路：演示 Payload 使用明确标注的宽有效期（2020～2099），保证教程可重复；严格边界仍由固定时间单元测试覆盖，不为生产验证 CLI 增加可由调用者伪造的“当前时间”参数。
- 验证办法：使用新临时目录重新执行生成密钥 → 签发 → 验证，必须输出 `License 验证成功`。

### 全仓库格式化产生无关历史文件差异

- 现象：`cargo fmt --all` 自动重排了 AES/ECDSA/RSA 演示、旧签发工具和 `main.rs`，diff 中出现数百行非功能性变化。
- 影响：扩大评审范围，掩盖 P1 实际改动，也不符合保留无关现有代码的原则。
- 原因：P1 新代码与历史未格式化代码共享同一 Cargo package，`--all` 会处理全部 target。
- 新思路：用补丁恢复 7 个历史文件到 HEAD，仅在确需通过严格 Clippy 的 `aes.rs`、`generate_key.rs`、`rsa.rs` 重新应用最小 API/warning 修复；后续只检查新文件格式，不再全仓库自动重排。
- 验证办法：最终 `git diff --stat` 不再包含 4 个纯格式文件，三个历史文件只保留最小语义等价差异；测试与 Clippy 仍通过。

## 实现后同步

| 需求项 | 实际文件/行为 | 验证证据 | 同步状态 |
| --- | --- | --- | --- |
| 分步文档与执行闭环 | `docs/steps/README.md`、P0～P5 步骤文档 | P0/P1 已填写前后核对及问题记录 | 一致 |
| 数据模型与只读上下文 | `src/license/model.rs` | Feature/Limit/Scope、机器策略和 FeatureDenied 测试 | 一致 |
| 确定性 CBOR 与有界解析 | `src/license/cbor.rs` | 固定向量、重编码校验、恶意长度预分配测试 | 一致 |
| Ed25519 域分离签发 | `src/license/signing.rs` | 相同输入字节一致、文件超限拒绝 | 一致 |
| KeyId 白名单和业务验证 | `src/license/validation.rs` | 篡改、未知/撤销/重复 KeyId、产品、时间、版本、机器测试 | 一致 |
| CLI 闭环 | `license_keygen`、`license_issue`、`license_verify` | 临时目录生成 32/32 字节密钥、270 字节 License 并验证成功 | 一致 |
| 跨语言基线 | `tests/vectors/ed25519-v1.json` | 237 字节固定 License，SHA-256 `fe1a8b...b836f` | 一致 |
| 自动化质量门 | 全部 target | 1 个内部测试 + 15 个集成测试通过；严格 Clippy 通过；diff check 通过 | 一致 |
| 私钥治理 | `.gitignore` 已扩充；历史 RSA 私钥仍在 Git | 风险已记录并转交 P5 轮换/历史清理 | 有记录的遗留风险 |

结论：P1 的离线签发、验证、授权上下文与工具链闭环已完成。P2 尚未开始；进入前必须先确定真实产品/SDK 的集成入口与高价值业务点。
