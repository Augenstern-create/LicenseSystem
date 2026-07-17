# LicenseSystem

Rust 商业软件 License 系统参考实现，依据《商业软件 License 架构设计方案》逐步实现。

项目覆盖离线签发与验签、产品授权集成、Windows 机器身份与时间锚、在线激活/租约/撤销、SQLite 持久化、TLS 管理面、备份恢复、签发治理和发布门禁。

> 当前状态：协议、单节点参考实现、测试和仓库内加固已经完成；生产发布仍被历史测试私钥、KMS/HSM、企业审批、代码签名和真实灾备等外部事项阻塞。

## 文档导航

- [项目架构](docs/ARCHITECTURE.md)
- [Rust、HTTP 与 CLI 接口](docs/API.md)
- [编译、运行与测试](docs/BUILD_AND_TEST.md)
- [后续事项总体路线图](docs/ROADMAP.md)
- [分步实施记录](docs/steps/README.md)
- [发布安全检查表](docs/release-checklist.md)
- [在线运维与恢复 Runbook](docs/runbooks/online-operations.md)
- [密钥轮换与泄漏响应](docs/runbooks/key-rotation-and-incident.md)

## 核心能力

- Ed25519 数字签名；
- 确定性 CBOR 和规范性重新编码检查；
- `ALIC` v1 信封、KeyId、公钥白名单和 generation；
- ACTIVE / VERIFY_ONLY / RETIRED / REVOKED 生命周期；
- 产品、时间、版本、机器策略验证；
- 不可变 `AuthorizationContext`；
- feature、limit、resource scope 业务路径约束；
- Windows SMBIOS UUID、MachineGuid、CPU 和卷序列号；
- HMAC/DPAPI 时间锚与回拨检测；
- 激活、浮动 Lease、TimeTicket、撤销代际和 replay 检查；
- SQLite WAL、外键、唯一约束和 immediate 事务；
- 公共/管理 TLS listener、Bearer 管理认证、限流和指标；
- SQLite 在线备份、完整性/schema/签名身份验证；
- 高风险双人审批、签发 receipt、fuzz 和 Python 跨语言向量。

## 模块

| 模块 | 说明 |
| --- | --- |
| `license` | 离线 Payload、CBOR、签发、验签、KeyRing 和治理签发 |
| `demo_sdk` | 虚拟图像 SDK，演示业务深度绑定 |
| `machine` | 机器信号采集、归一化、哈希与加权匹配 |
| `time_anchor` | 受保护本地状态与时间回拨检测 |
| `online` | 激活、Lease、TimeTicket、SQLite、HTTP、管理和运维 |
| `src/bin` | 密钥、签发、验证、Demo、Server 和备份 CLI |

`src/aes.rs`、`src/ecdsa.rs`、`src/rsa.rs` 是历史算法演示，不是正式 License 入口。

## 环境

- Rust stable，edition 2024；
- Windows 建议使用 PowerShell；
- Python 跨语言验证需要 Python 3 + cryptography；
- fuzz 正式运行需要 nightly + cargo-fuzz；
- TLS 手工测试可使用 OpenSSL。

如果 Cargo 不在 PATH：

```powershell
& "$env:USERPROFILE\.cargo\bin\cargo.exe" --version
```

## 编译

检查：

```powershell
cargo check --all-targets
```

Debug：

```powershell
cargo build --all-targets
```

Release：

```powershell
cargo build --release --lib `
  --bin online_secure_server `
  --bin online_backup_verify `
  --bin license_issue_governed
```

生成严格 rustdoc：

```powershell
$env:RUSTDOCFLAGS = '-D missing-docs -D rustdoc::broken-intra-doc-links'
cargo doc --no-deps --lib
Remove-Item Env:RUSTDOCFLAGS
```

详细说明见 [编译与测试指南](docs/BUILD_AND_TEST.md)。

## 离线 License 快速开始

### 1. 生成开发密钥

```powershell
cargo run --bin license_keygen -- `
  keys/dev-private.key keys/dev-public.key
```

生成的文件只用于开发。生产私钥必须进入 KMS/HSM 或隔离签名系统。

### 2. 签发

```powershell
cargo run --bin license_issue -- `
  licenses/payload.example.json `
  keys/dev-private.key dev-2026-01 licenses/dev.lic
```

`license_issue` 是早期开发 CLI，不进入生产发布包。

### 3. 验证

```powershell
cargo run --bin license_verify -- `
  licenses/dev.lic keys/dev-public.key dev-2026-01 image-sdk
```

### 4. 治理签发

```powershell
cargo run --bin license_issue_governed -- `
  request.json keys/isolated-private.key prod-2026 3 `
  output.lic receipt.json
```

治理入口执行：

- generation 检查；
- ACTIVE key 检查；
- 永久、超期限或超额度双人审批；
- License SHA-256 receipt；
- 输出文件拒绝覆盖。

## 产品集成 Demo

```powershell
cargo run --bin sdk_demo -- `
  licenses/dev.lic keys/dev-public.key dev-2026-01 `
  image-sdk M001 CAM-001
```

虚拟 SDK 实际约束：

- GPU/DeepZoom/Batch 算法注册；
- 并行任务；
- 模型 ID；
- 设备 ID 与设备数量。

它不依赖单一可写 `isLicensed` 布尔值。

## Windows 机器身份

```powershell
cargo run --bin machine_code -- image-sdk
```

输出只包含产品域分离 SHA-256 指纹、权重和可信等级，不输出原始机器值。

## 时间锚

```powershell
cargo run --bin time_anchor_demo -- `
  target/demo-anchor.state `
  2fd44c80-52ca-4b0a-9636-fd88b7d3cc0e
```

Windows 使用 DPAPI 绑定当前用户。默认允许 6 小时小幅校时，超过容忍范围返回 `LIC_TIME_ROLLBACK`。

## 在线服务

### 内存端到端 Demo

```powershell
cargo run --bin online_demo
```

流程：entitlement → activation → Lease/TimeTicket → 本地验签 → revoke。

### SQLite 参考 Server

```powershell
cargo run --bin online_sqlite_server -- `
  target/online-demo.sqlite 127.0.0.1:3000
```

首次启动输出 `license_id`。重启时把该 ID 作为第三个参数传回，可复用 entitlement 和持久化状态。

### TLS 安全参考 Server

```powershell
$env:LICENSE_ADMIN_TOKEN = '<至少 32 字节高熵 token>'
$env:LICENSE_ADMIN_CREDENTIAL_ID = 'ops-admin'

cargo run --bin online_secure_server -- `
  data/license.sqlite online-prod-2026 keys/online-private.key `
  tls/fullchain.pem tls/private-key.pem backups `
  0.0.0.0:3443 127.0.0.1:3444
```

- 公共 API：`/v1/activate`、`/v1/lease`、`/v1/time-ticket`；
- 管理 API：entitlement、revoke、deactivate、audit、metrics、backup；
- 管理 listener 强制 loopback；
- 数据库不保存在线签名私钥。

HTTP JSON 示例见 [接口文档](docs/API.md)。

## 备份验证

```powershell
cargo run --bin online_backup_verify -- `
  backups/license-backup-<timestamp>-<uuid>.sqlite `
  online-prod-2026 keys/online-public.key
```

验证内容：

- SQLite `integrity_check`；
- schema version；
- KeyId；
- Ed25519 公钥身份。

## 测试

全量：

```powershell
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

按测试文件：

```powershell
cargo test --test license_core
cargo test --test online_service
cargo test --test online_sqlite
```

运行单个测试函数：

```powershell
cargo test --test online_service `
  concurrent_lease_allocation_never_exceeds_quota `
  -- --exact --nocapture
```

按名称过滤：

```powershell
cargo test stale_tokens_are_rejected -- --nocapture
```

测试文件与每个主要测试函数的用途见 [编译与测试指南](docs/BUILD_AND_TEST.md#12-测试文件与主要函数)。

## Fuzz 与跨语言验证

编译 fuzz target：

```powershell
cargo check --manifest-path fuzz/Cargo.toml
```

运行 Python 独立向量：

```powershell
python scripts/verify_license_vector.py
```

Python 脚本独立解析/规范重编码 CBOR，并使用 cryptography 验证 Ed25519 和域分离。

## 发布检查

```powershell
./scripts/release_secret_audit.ps1 -AuditOnly
./scripts/check_markdown_links.ps1
git diff --check
```

正式秘密审计：

```powershell
./scripts/release_secret_audit.ps1
```

当前正式模式会因 Git 跟踪的 `keys/rsa_private.der` 返回退出码 2。这是预期发布阻塞项；未经仓库所有者审批，本项目没有删除文件或重写 Git 历史。

## 当前生产限制

- 尚未接入生产 KMS/HSM；
- 管理认证仍是单高熵 Bearer token；
- SQLite 是单节点；
- 指标是进程内累计；
- 客户端 replay cache 尚未持久化；
- 尚无企业审批、代码签名、SBOM、集中监控和真实灾备证据；
- 历史 RSA 私钥仍在 Git 历史。

后续顺序、责任矩阵和发布准入见 [总体路线图](docs/ROADMAP.md)。

## 安全提示

- 仓库内历史私钥、测试 seed 和 Demo 固定 key 全部视为公开；
- 客户端只分发公钥；
- 不记录完整 License、管理员 token、原始机器标识或完整 customer_id；
- 完全离线 License 无法实时撤销，该边界需要产品和合同共同约束；
- 测试通过不等于生产治理和基础设施已完成。
