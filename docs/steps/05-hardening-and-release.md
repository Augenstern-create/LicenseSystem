# P5：签发治理、加固与发布

## 目标

把可运行的 License 系统提升为可安全运营、轮换、审计、恢复和发布的商业软件基础设施。

## 实现前确认（进入本步骤时填写）

- [x] P1～P4 仓库内实现已完成：离线核心、SDK、机器/时间、在线协议、SQLite、TLS/管理/备份参考能力共 63 项测试通过。
- [ ] 生产 KMS/HSM、审批人、值班人和事件响应责任人已确定。当前仓库和环境未提供，属于发布阻塞项。
- [ ] 明确客户端支持周期、最长 License 生命周期和旧 Key 移除条件。需要产品与客户支持负责人确认，仓库只能提供决策模板。
- [x] 初步盘点发现 Git 跟踪 `keys/rsa_private.der`；它及历史演示密钥必须视为已泄漏测试秘密，禁止用于生产。

状态：P5 实现前盘点进行中；先完成仓库内可验证加固，再形成外部发布阻塞清单。

## 详细实现事项

### 本轮仓库内可完成任务

1. [x] 为 `TrustedKey` 增加 generation，并让 `KeyRing` 支持 minimum generation；验证 ACTIVE/VERIFY_ONLY 可验签，RETIRED/REVOKED 或低代际失败关闭。
2. [x] 增加受治理签发入口：仅 ACTIVE key 可签发，永久/超期限/超额度请求需要至少两个不同且非请求人的审批标识。
3. [x] 生成不含私钥的签发 receipt：LicenseId、KeyId、generation、请求人、审批人、文件 SHA-256 和签发时间，供外部不可变审计接收。
4. [x] 增加解析器随机/突变稳健性测试，固定输入、迭代预算和最大文件尺寸；增加 cargo-fuzz 入口但不把 nightly 工具链作为普通构建依赖。
5. [x] 增加 Python 独立验证脚本：自行解析固定向量的 CBOR 信封并用 Python cryptography 验证 Ed25519、域分离和 SHA-256。
6. [x] 增加秘密/私钥发布扫描，明确识别已跟踪 `keys/rsa_private.der` 并让正式发布检查失败。
7. [x] 增加发布清单、密钥轮换/泄漏、客户迁移/解绑/离线续期、Git 历史清理 Runbook。
8. [x] 增加 release profile 加固、发布包允许列表和日志脱敏规则说明。
9. [x] 运行全量测试、严格 Clippy、Python 跨语言验证、秘密扫描预期阻断和 diff check。

### 必须由组织或外部平台完成的任务

1. [ ] 选定并接入生产 KMS/HSM，证明私钥不可导出，建立开发/测试/生产独立信任根。
2. [ ] 接入企业身份与双人审批系统，把代码中的审批标识替换为经认证主体和不可变审计。
3. [ ] 确认支持周期、最长 License 生命周期、旧 Key 移除条件、RPO/RTO、SLA 和责任人。
4. [ ] 获取代码签名证书，建立受保护的 CI 发布流水线、制品签名和渠道验证。
5. [ ] 经仓库所有者审批后轮换历史 RSA 测试信任根，并使用 git-filter-repo/BFG 清理历史；通知所有协作者重新克隆。
6. [ ] 在真实监控、备份和灾备平台完成演练并签署发布检查表。

### 签发与密钥

1. 生产签发只接受经过认证授权的结构化请求，不接受任意待签名字节。
2. 私钥保存在 HSM/KMS/隔离签名服务，开发、测试、生产信任根隔离。
3. 实现 ACTIVE → VERIFY_ONLY → RETIRED/REVOKED 生命周期及客户端 minimum generation。
4. 高权限、永久、超额度 License 使用双人审批和不可变审计。
5. 清理仓库中历史演示私钥；由于 `rsa_private.der` 已跟踪，执行轮换和 Git 历史清理方案。

### 客户端与质量

1. 模糊测试信封和 Payload 解码器，设置内存/时间预算。
2. 固定跨语言测试向量，至少验证 Rust 与一个服务端/客户端语言字节一致。
3. 完整性检测、代码签名、发布渠道校验和崩溃日志脱敏。
4. 错误提示最小披露，内部日志包含原因码、KeyId、LicenseId 后缀和版本。
5. 性能、并发、断电、权限、只读目录和原子替换测试。

### 运维与演练

1. 私钥泄漏、误撤销、KMS 不可用、数据库恢复和时钟异常 Runbook。
2. 密钥轮换、备份恢复和撤销演练，记录恢复时间与改进项。
3. 客户迁移、解绑、离线续期和支持工具流程。
4. 发布前安全检查表逐项签字。

## 验收标准

- 客户端和分发包不含生产私钥/共享签发秘密。
- 生产签发、审批、撤销、轮换和恢复均有审计与演练证据。
- 模糊测试、跨语言向量、代码签名和完整发布流水线通过。
- 已跟踪演示私钥完成轮换与经批准的历史处理。
- 运维手册与客户支持流程可实际执行。

## 问题与新思路

### 发布扫描只看已跟踪文件且可能匹配自身规则文本

- 现象：初版使用 `git ls-files`，本轮尚未提交的新源码不在扫描范围；脚本一旦被跟踪，其源码中的完整 PEM marker 正则也可能触发自身内容扫描。
- 影响：前者可能漏报待发布新文件，后者可能在提交后产生假阳性。
- 新思路：扫描“Git 跟踪文件 + `rg --files` 当前非忽略文件”的去重并集；把 PEM marker 字符串分段拼接，源码不再包含可被自身匹配的连续 marker。
- 验证办法：AuditOnly 扫描候选数大于当前 20 个 tracked 文件，只报告真实历史 RSA 私钥；正式模式仍稳定退出 2。

### 治理 CLI 测试夹具被策略判定为高风险

- 现象：`governed_cli` 集成测试直接复用 `licenses/payload.example.json` 且未提供审批，CLI 按策略返回“需要两个独立审批人”。
- 影响：1 个新测试失败；治理策略正确失败关闭，没有生成 License/receipt。
- 原因：实际夹具有效期为 2020-01-01 至 2099-12-31，远超默认 366 天标准阈值；不能依据另一个固定向量推断。
- 新思路：读取实际夹具；集成测试应显式把期限和额度设置在标准阈值内，双人审批逻辑继续由独立高风险测试覆盖。
- 验证办法：修正测试输入后 CLI 成功生成 receipt，并用 generation 7 公钥验签。

### 秘密审计脚本的 Write-Error 会破坏约定退出码

- 现象：脚本设置 `$ErrorActionPreference='Stop'` 后若调用 `Write-Error`，PowerShell 会在显式 `exit 2` 前终止。
- 影响：CI 无法稳定区分“发现发布 blocker”（预期 2）和“脚本自身故障”（其他非零）。
- 新思路：以普通输出打印阻断结论并显式 `exit 2`；AuditOnly 保持 0，脚本异常仍由 Stop 策略产生其他非零退出。
- 验证办法：AuditOnly 输出 1 个 blocker 且退出 0；正式模式输出相同 blocker 且退出码严格为 2。

### Rust 2024 与 rand 0.8 的 gen 方法同名

- 现象：解析稳健性测试初稿调用 `random.gen()`；`gen` 在 Rust 2024 是保留关键字。
- 影响：继续格式化/编译会出现语法错误，尚未影响业务代码。
- 新思路：保留现有 rand 0.8 依赖，改用 `RngCore::next_u32` 截取字节；固定 RNG seed 保持测试可复现。
- 验证办法：定向 rustfmt、编译并运行 4000 轮随机/突变输入测试。

### 初次源码盘点使用了规划名而非实际模块名

- 现象：尝试读取 `src/license/keys.rs`、`issuer.rs`、`validator.rs`，实际文件是 `signing.rs` 和 `validation.rs`，三次读取失败。
- 影响：没有修改代码，只说明规划模块名与最终落盘结构不同。
- 新思路：以 `rg --files` 为真实清单，读取 `signing.rs`、`validation.rs`、`cbor.rs` 和公开导出后再冻结 P5 任务。
- 验证办法：P5 实现后同步表同时记录规划名与实际文件，不为名称一致性做无价值重构。

### P5 文档首次补丁上下文未匹配

- 现象：补丁使用了不含“（进入本步骤时填写）”的标题上下文，校验失败且未应用任何修改。
- 影响：没有部分更新；仅增加一次文档操作往返。
- 新思路：读取带行号原文后使用清单行作为最小上下文。
- 验证办法：本节和实现前清单成功写入后再继续源码动作。

### Git 正在跟踪历史 RSA 私钥

- 现象：`git ls-files` 确认 `keys/rsa_private.der` 已纳入版本控制；公钥和历史签名样例也在仓库。
- 影响：该私钥必须视为已泄漏，任何由它代表的信任根都不能进入生产；仅删除当前文件也不能清除 Git 历史。
- 新思路：本步骤先增加秘密扫描与发布阻断规则、把该材料列入永久测试黑名单，并编写经审批后执行的历史清理 Runbook。未经用户明确授权不重写 Git 历史或删除用户样例文件。
- 验证办法：发布检查必须识别该已知文件；生产材料清单必须为空；历史清理保持人工审批门槛。

后续问题按时间追加；任何代码调整前先记录。

## 实现后同步

### 仓库内实现结果

| 领域 | 实际结果 | 状态 |
| --- | --- | --- |
| 密钥生命周期 | `TrustedKey.generation`、`KeyRing.minimum_generation`；ACTIVE/VERIFY_ONLY 验签，RETIRED/REVOKED/低代际拒绝 | 完成 |
| 受治理签发 | `GovernedSigner` 只允许 ACTIVE；永久、超过 366 天或额度超过策略阈值需要两个独立非请求人审批 | 完成 |
| 签发审计 | receipt 包含 LicenseId、KeyId、generation、请求/审批人、signed_at、License SHA-256，不含私钥和 customer_id | 完成；外部不可变存储待接入 |
| 签发 CLI | `license_issue_governed` 读取结构化请求，拒绝覆盖，生成 `.lic` 与 receipt；失败时不保留孤立 License | 完成；本地私钥文件仅适合隔离环境 |
| 解析稳健性 | 固定 seed 的 2000 随机 + 2000 突变输入无 panic；cargo-fuzz target 可编译 | 完成；持续 fuzz 待 CI 预算 |
| 跨语言 | Python 自行解码/重编码 CBOR，用 cryptography 验证 Ed25519 域分离和固定 SHA-256 | 完成 |
| 发布扫描 | 扫描 20 个 tracked、111 个候选文件；准确识别测试向量和 1 个真实 blocker | 完成并阻断发布 |
| Runbook | 密钥轮换/泄漏、Git 历史清理、客户支持、在线运维、发布检查表和包允许列表 | 完成模板 |
| 构建 | release profile 启用 thin LTO、单 codegen unit、overflow checks、panic abort、strip | 完成 |

### 验证证据

- `cargo test --all-targets`：69 项全部通过。
- `cargo clippy --all-targets -- -D warnings`：通过，零 Clippy 告警。
- `cargo check --manifest-path fuzz/Cargo.toml`：libFuzzer target 编译通过。
- `scripts/verify_license_vector.py`：输出 `python_vector_verification=ok`，SHA-256 与 Rust 固定向量一致。
- `release_secret_audit.ps1 -AuditOnly`：退出 0，报告测试 seed 和 `keys/rsa_private.der` blocker；正式模式稳定退出 2。
- Release profile 成功构建 library、`online_secure_server`、`online_backup_verify`、`license_issue_governed`。
- `git diff --check`：退出码 0；Windows linker/行尾提示已分别记录，不作为代码告警隐藏。

### 发布阻塞项

1. `keys/rsa_private.der` 仍在 Git 当前版本和历史中；未经仓库所有者批准，本步骤没有删除或重写历史。
2. 没有生产 KMS/HSM、不可导出证明、生产 KeyId/generation 和环境隔离证据。
3. 没有企业身份/双人审批系统、不可变审计平台和已指定责任人。
4. 没有代码签名证书、受保护 CI、SBOM/制品签名和正式发布渠道证据。
5. 没有已批准的支持周期、最长 License 生命周期、SLA、RPO/RTO 和客户迁移政策。
6. 没有真实 WAF/集中监控/不可变异地备份/多节点灾备演练证据。
7. cargo-fuzz 入口已编译，但持续 fuzz 时长、corpus、crash 归档需要 CI/nightly 环境执行。

### 发布结论

仓库内设计与参考实现流程已走完，自动质量门禁通过；生产发布结论为“阻塞”，不能标记为可上线。解除以上阻塞需要仓库所有者、安全、运维、产品支持和发布负责人提供授权、基础设施和签字证据。

状态：P5 仓库内加固已完成；生产发布受外部治理和历史私钥处理阻塞。
