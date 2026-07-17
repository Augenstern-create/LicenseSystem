# 编译、运行与测试指南

## 1. 环境要求

- Rust stable，项目 edition 2024；
- Cargo；
- Windows 机器功能测试需要 Windows Registry、SMBIOS、DPAPI；
- Python 跨语言验证需要 Python 3 和 `cryptography`；
- TLS 手工演练可使用 OpenSSL 生成测试证书；
- cargo-fuzz 正式运行需要 nightly 和 `cargo install cargo-fuzz`。

本仓库在 Windows PowerShell 中开发。若 Cargo 不在 PATH，可使用：

```powershell
& "$env:USERPROFILE\.cargo\bin\cargo.exe" --version
```

## 2. 获取与检查

```powershell
git status
cargo metadata --no-deps
cargo check --all-targets
```

仓库当前包含未提交开发变更时，不要使用 `git reset --hard` 或覆盖用户文件。

## 3. Debug 编译

编译全部库、CLI 和测试目标：

```powershell
cargo build --all-targets
```

仅编译库：

```powershell
cargo build --lib
```

仅编译安全在线服务：

```powershell
cargo build --bin online_secure_server
```

产物位于 `target/debug/`。

## 4. Release 编译

```powershell
cargo build --release --lib `
  --bin online_secure_server `
  --bin online_backup_verify `
  --bin license_issue_governed
```

release profile：

- thin LTO；
- `codegen-units = 1`；
- overflow checks；
- panic abort；
- strip symbols。

优化产物位于 `target/release/`。正式打包必须按 [发布包允许列表](../release/package-allowlist.md) 从空目录复制，不得压缩整个仓库。

## 5. 生成 rustdoc

普通文档：

```powershell
cargo doc --no-deps --lib
```

严格检查公共 API 注释和链接：

```powershell
$env:RUSTDOCFLAGS = '-D missing-docs -D rustdoc::broken-intra-doc-links'
cargo doc --no-deps --lib
Remove-Item Env:RUSTDOCFLAGS
```

入口：`target/doc/license_system/index.html`。

## 6. 离线 License 快速演练

生成开发密钥：

```powershell
cargo run --bin license_keygen -- `
  keys/dev-private.key keys/dev-public.key
```

签发：

```powershell
cargo run --bin license_issue -- `
  licenses/payload.example.json `
  keys/dev-private.key dev-2026-01 licenses/dev.lic
```

验证：

```powershell
cargo run --bin license_verify -- `
  licenses/dev.lic keys/dev-public.key dev-2026-01 image-sdk
```

输出文件默认拒绝覆盖。重复演练请使用新路径或明确删除 `target/`/开发文件。

## 7. 治理签发

请求 JSON：

```json
{
  "payload": {
    "schema_version": 1,
    "license_id": "2fd44c80-52ca-4b0a-9636-fd88b7d3cc0e",
    "product_id": "image-sdk",
    "edition": "enterprise",
    "customer_id": "CUST-10086",
    "issued_at": "2026-01-15T00:00:00Z",
    "not_before": null,
    "expires_at": "2026-12-31T00:00:00Z",
    "maintenance_until": null,
    "license_type": "site",
    "features": {"gpu": true},
    "limits": {"max_parallel_jobs": 8},
    "resource_scope": {},
    "machine_policy": null,
    "min_app_version": null,
    "max_app_version": null,
    "revocation_epoch": 0,
    "custom": {}
  },
  "requested_by": "issuer-user",
  "approved_by": []
}
```

命令：

```powershell
cargo run --bin license_issue_governed -- `
  request.json keys/isolated-private.key prod-2026 3 `
  output.lic receipt.json
```

永久、超过默认 366 天或额度超过 10000 的请求需要至少两个不同且非请求人的 `approved_by`。

## 8. Demo

虚拟 SDK：

```powershell
cargo run --bin sdk_demo -- `
  licenses/dev.lic keys/dev-public.key dev-2026-01 `
  image-sdk M001 CAM-001
```

机器指纹：

```powershell
cargo run --bin machine_code -- image-sdk
```

时间锚：

```powershell
cargo run --bin time_anchor_demo -- `
  target/demo-anchor.state `
  2fd44c80-52ca-4b0a-9636-fd88b7d3cc0e
```

在线内存流程：

```powershell
cargo run --bin online_demo
```

SQLite 参考 Server：

```powershell
cargo run --bin online_sqlite_server -- `
  target/online-demo.sqlite 127.0.0.1:3000
```

## 9. 安全 TLS Server

准备：

- 32 字节 Ed25519 私钥文件；
- PEM 证书与证书私钥；
- SQLite 路径；
- 备份目录；
- 至少 32 字节管理员 token。

```powershell
$env:LICENSE_ADMIN_TOKEN = '<high-entropy-secret>'
$env:LICENSE_ADMIN_CREDENTIAL_ID = 'ops-admin'

cargo run --bin online_secure_server -- `
  data/license.sqlite online-prod-2026 keys/online-private.key `
  tls/fullchain.pem tls/private-key.pem backups `
  0.0.0.0:3443 127.0.0.1:3444
```

管理地址必须是 loopback。生产远程管理应经过 VPN、堡垒机或 mTLS 代理。

## 10. 全量质量检查

```powershell
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
python scripts/verify_license_vector.py
./scripts/release_secret_audit.ps1 -AuditOnly
./scripts/check_markdown_links.ps1
git diff --check
```

正式发布秘密检查不加 `-AuditOnly`。当前会因 `keys/rsa_private.der` 返回退出码 2。

## 11. 按测试文件运行

```powershell
cargo test --test license_core
cargo test --test demo_sdk
cargo test --test machine_identity
cargo test --test time_anchor
cargo test --test online_service
cargo test --test online_http
cargo test --test online_sqlite
cargo test --test online_admin
cargo test --test online_backup
cargo test --test license_governance
cargo test --test governed_cli
cargo test --test license_parser_robustness
```

运行单个测试函数：

```powershell
cargo test --test online_service concurrent_lease_allocation_never_exceeds_quota -- --exact --nocapture
```

按名称过滤所有目标：

```powershell
cargo test stale_tokens_are_rejected -- --nocapture
```

## 12. 测试文件与主要函数

### `tests/license_core.rs`

- `valid_license_builds_immutable_authorization_context`：合法 License 到授权上下文；
- `issuing_the_same_payload_is_deterministic`：确定性签发；
- `a_single_byte_signature_tamper_is_rejected`：签名篡改；
- `an_untrusted_key_id_is_rejected`、`a_revoked_key_is_rejected`：信任根；
- `an_expired_license_is_rejected`：到期边界；
- `a_product_mismatch_is_rejected`：产品隔离；
- `machine_policy_requires_threshold_and_high_confidence_match`：机器策略；
- `oversized_and_trailing_data_are_rejected`：尺寸和尾随数据；
- `unknown_algorithm_is_rejected_before_verification`：算法白名单；
- `validity_and_version_boundaries_fail_closed`：时间/版本/维护期；
- `node_locked_and_field_shape_rules_are_enforced_before_signing`：签发前 schema；
- `issuer_rejects_a_model_that_encodes_beyond_the_file_limit`：编码后上限；
- `duplicate_key_id_does_not_replace_the_original_trust_anchor`：KeyId 替换攻击；
- `fixed_v1_vector_is_available_for_other_languages`：固定向量。

### `tests/license_governance.rs`

- `minimum_generation_and_key_lifecycle_fail_closed`；
- `governed_signer_only_issues_with_an_active_key`；
- `high_risk_issuance_requires_two_independent_approvers`；
- `standard_issuance_does_not_require_dual_approval`。

### `tests/governed_cli.rs`

- `governed_cli_writes_a_verifiable_license_and_receipt`：真实启动 CLI，验证 `.lic` 和 receipt。

### `tests/license_parser_robustness.rs`

- `random_and_mutated_inputs_never_panic_or_exceed_input_budget`：固定 seed，2000 随机 + 2000 突变输入。

### `tests/demo_sdk.rs`

- feature 与算法注册；
- 模型 scope；
- 并行额度、RAII 和竞争；
- 设备 scope、数量和幂等；
- 缺少必需额度时拒绝构造。

### `tests/machine_identity.rs`

- 归一化和产品域分离；
- 中权重硬件变化容忍；
- threshold/high-confidence 双条件；
- 重复信号不重复计分。

### `tests/time_anchor.rs`

- HMAC/DPAPI；
- 首次创建和时间前进；
- 小幅校时；
- UTC/单调时钟回拨；
- 状态篡改、删除和独占锁。

### `tests/online_service.rs`

- 激活配额和幂等；
- request_id 冲突；
- 激活/feature 前置条件；
- 16 线程席位竞争；
- 过期回收；
- 同 installation 续租；
- token 篡改、时间、epoch；
- Lease/TimeTicket replay；
- 撤销和审计。

### `tests/online_http.rs`

- 公共 HTTP 成功合约；
- 稳定 JSON 错误；
- 管理路由不公开。

### `tests/online_sqlite.rs`

- 重启恢复和持久化幂等；
- 两个独立连接不超发；
- 重启后过期回收；
- schema/epoch 边界；
- 签名身份误配；
- 外键和唯一约束；
- 共用 HTTP Router。

### `tests/online_admin.rs`

- 管理认证和 actor；
- 公共/管理隔离；
- 429 与指标；
- 413 body 上限；
- 服务端生成备份路径。

### `tests/online_backup.rs`

- 在线备份恢复状态和 token；
- 拒绝覆盖和损坏失败关闭。

## 13. Fuzz

编译 fuzz target：

```powershell
cargo check --manifest-path fuzz/Cargo.toml
```

安装并运行：

```powershell
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run license_decode -- -max_len=65537 -max_total_time=300
```

corpus 和 artifacts 默认被 `.gitignore` 排除。CI 应保存 crash 输入作为安全证据，但不得保存客户 License。

## 14. Python 跨语言向量

```powershell
python scripts/verify_license_vector.py
```

脚本不调用 Rust：

- 独立解析和规范重编码 CBOR；
- 验证 ALIC 字段；
- 使用 Python cryptography 验证 Ed25519；
- 验证 domain separator、Payload 字段和 SHA-256。

## 15. 临时文件

测试和 Demo 临时文件位于：

- `target/online-sqlite-tests/`
- `target/online-admin-tests/`
- `target/online-backup-tests/`
- `target/governed-cli-tests/`
- `target/secure-demo/`

测试通常自行清理。手工 Demo 产物位于 `target/`，可在确认路径后删除。

## 16. 常见问题

### Cargo 不在 PATH

使用 `$env:USERPROFILE\.cargo\bin\cargo.exe`。

### Windows linker_messages

MSVC 可能输出“正在创建库 ... `.lib/.exp`”提示。它不影响 Clippy 结果；不要全局屏蔽真实链接告警。

### LF/CRLF 提示

Git 可能提示下次触碰时转换行尾。当前不批量改写用户原文件；后续由 `.gitattributes` 策略单独决定。

### SQLite 签名身份不匹配

数据库保存 KeyId 和公钥。必须用原在线私钥/KeyId 打开，不能给相同 KeyId 换公钥。

### 正式秘密审计失败

这是预期发布 blocker：仓库仍跟踪历史 RSA 私钥。处理流程见 [Git 历史清理 Runbook](runbooks/git-history-secret-cleanup.md)。
