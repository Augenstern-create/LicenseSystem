# LicenseSystem 接口文档

## 1. Rust 离线 API

主要类型从 crate 根导出：

```rust
use license_system::{
    KeyRing, KeyStatus, LicensePayload, TrustedKey, ValidationInput,
    issue_license, validate_license,
};
```

### 1.1 签发

```rust
let bytes = issue_license(&payload, "prod-2026-01", &signing_key)?;
```

`issue_license`：

- 输入必须是 `LicensePayload`，不接受任意待签名字节；
- 校验字段形状、时间关系、node-locked 策略和 64 KiB 上限；
- 生成规范 CBOR；
- 使用 Ed25519 对版本化 domain + payload 签名；
- 返回完整 `ALIC` 文件字节。

生产或隔离签发优先使用：

```rust
let signer = GovernedSigner::new(
    "prod-2026-01",
    3,
    KeyStatus::Active,
    signing_key,
    IssuancePolicy::default(),
)?;
let issued = signer.issue(&request, signed_at)?;
```

`GovernedSigner` 额外执行：

- 只允许 `Active` key；
- generation 必须大于零；
- 永久、超过标准有效期或超额度请求需要两个独立非请求人审批；
- 返回 License bytes 和不含私钥的 `IssuanceReceipt`。

### 1.2 验证

```rust
let mut keys = KeyRing::with_minimum_generation(3);
keys.insert(TrustedKey::ed25519_with_generation(
    "prod-2026-01",
    3,
    KeyStatus::Active,
    public_key,
))?;

let input = ValidationInput::new("image-sdk", trusted_now);
let context = validate_license(&license_bytes, &input, &keys)?;
```

`validate_license` 验证顺序：

1. 文件大小；
2. ALIC magic、版本、算法白名单；
3. 规范 CBOR；
4. KeyId、公钥、状态和 generation；
5. Ed25519 签名；
6. Payload schema；
7. product、时间、应用版本、维护日期；
8. 可选机器策略。

成功返回不可变 `AuthorizationContext`：

| 方法 | 用途 |
| --- | --- |
| `license_id()` | 获取 License UUID |
| `product_id()` | 获取已验证产品 |
| `edition()` | 获取商业版本 |
| `customer_id()` | 可信业务系统使用 |
| `expires_at()` | 可选到期时间 |
| `has_feature(name)` | 查询功能 |
| `require_feature(name)` | 强制功能授权 |
| `get_limit(name, default)` | 查询数值额度 |
| `get_resource_scope(name)` | 查询资源 allowlist |

## 2. Payload 字段

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `schema_version` | u16 | 当前为 1 |
| `license_id` | UUID | 全局唯一 |
| `product_id` | string | 必须与产品一致 |
| `edition` | string | 商业版本 |
| `customer_id` | string | 客户标识 |
| `issued_at` | RFC3339 | 签发时间 |
| `not_before` | RFC3339/null | 可选生效时间 |
| `expires_at` | RFC3339/null | 可选到期；null 为永久高风险 |
| `maintenance_until` | RFC3339/null | 最晚可运行新构建日期 |
| `license_type` | enum | trial/node_locked/subscription/floating/site |
| `features` | map[string,bool] | 功能开关 |
| `limits` | map[string,u64] | 额度 |
| `resource_scope` | map[string,array] | 模型、设备等 allowlist |
| `machine_policy` | object/null | 指纹集合和阈值 |
| `min_app_version` | SemVer/null | 最低版本 |
| `max_app_version` | SemVer/null | 最高版本 |
| `revocation_epoch` | u64 | 签发时撤销代际 |
| `custom` | map[string,string] | 有界扩展 |

## 3. 虚拟图像 SDK

```rust
let sdk = DemoImageSdk::new(context)?;
let permit = sdk.start_job()?;
let receipt = sdk.run_algorithm(AlgorithmKind::Gpu, "M001")?;
let connected = sdk.connect_device("CAM-001")?;
drop(permit);
```

| 方法 | 授权消费 |
| --- | --- |
| `new` | 读取并验证必需额度 |
| `registered_algorithms` | feature 决定注册算法 |
| `start_job` | 原子限制 `max_parallel_jobs` |
| `run_algorithm` | 同时验证算法 feature 和 `model_ids` |
| `connect_device` | 同时验证 `device_ids` 和 `max_devices` |
| `disconnect_device` | 幂等释放设备 |

## 4. 机器身份 API

```rust
let identity = collect_machine_identity(
    "image-sdk",
    &WindowsMachineSignalCollector,
)?;
```

测试或其他平台可自行实现 `MachineSignalCollector`，或调用：

```rust
let identity = derive_machine_identity("image-sdk", signals)?;
```

原始信号只用于当前进程归一化和哈希，不应进入日志或服务端数据库。

## 5. 时间锚 API

Windows：

```rust
let store = TimeAnchorStore::new(path, DpapiStateProtector);
let observation = store.observe(license_id, now, monotonic_ms)?;
```

跨平台测试：

```rust
let protector = HmacStateProtector::new([7; 32]);
let store = TimeAnchorStore::new(path, protector)
    .with_rollback_tolerance(Duration::from_secs(3600));
```

状态：

- `Created`：首次安装；
- `Advanced`：时间正常前进；
- `AdjustedWithinTolerance`：小幅回拨但未降低可信 UTC；
- `TimeAnchorError::RollbackDetected`：超过容忍范围。

## 6. 在线服务 Rust API

### 6.1 内存后端

```rust
let service = OnlineLicenseService::new("online-key", signing_key)?;
```

适合协议测试和 Demo，进程退出后状态丢失。

### 6.2 SQLite 后端

```rust
let service = SqliteOnlineLicenseService::open(
    "data/license.sqlite",
    "online-key",
    signing_key,
)?;
```

关键方法：

| 方法 | 说明 |
| --- | --- |
| `register_entitlement` | 管理端注册配额 |
| `activate` | 安装激活与幂等 |
| `issue_lease` | 原子席位分配/续租 |
| `issue_time_ticket` | 服务器时间票据 |
| `release_lease` | 显式释放 |
| `deactivate` | 解绑安装 |
| `revoke_license` | 撤销并提高 epoch |
| `audit_events` | 读取审计 |
| `backup_to` | 在线备份，拒绝覆盖 |
| `verify_backup_identity` | 完整性/schema/公钥身份检查 |

所有 `now` 参数均为服务端 UTC Unix 秒，不接受客户端时间作为授权依据。

## 7. 客户端在线 token

```rust
let verifier = OnlineTokenVerifier::new(key_id, online_public_key)?;
let claims = verifier.verify_lease(
    &signed_lease,
    expected_license_id,
    expected_installation_id,
    trusted_now,
    minimum_revocation_epoch,
)?;
```

校验内容：

- Base64 和规范 CBOR；
- token 类型和 KeyId；
- Ed25519 domain；
- LicenseId/installation_id；
- issued/expires；
- minimum revocation epoch；
- 进程内 replay 顺序。

`verify_time_ticket` 使用相同模式。

## 8. 公共 HTTP API

Content-Type：`application/json`  
最大 body：64 KiB  
UUID 均为标准字符串；时间均为 UTC Unix 秒。

### POST `/v1/activate`

请求：

```json
{
  "request_id": "35f1a13b-ced9-4aa3-afac-501a1687c1e0",
  "license_id": "2fd44c80-52ca-4b0a-9636-fd88b7d3cc0e",
  "installation_id": "6af18735-82ae-42f7-bb7f-f8a4387d32f7"
}
```

响应：

```json
{
  "activation_id": "33ce55cf-3d7e-41b7-afab-274927e5f627",
  "license_id": "2fd44c80-52ca-4b0a-9636-fd88b7d3cc0e",
  "installation_id": "6af18735-82ae-42f7-bb7f-f8a4387d32f7",
  "activated_at": 1784057637,
  "revocation_epoch": 0
}
```

### POST `/v1/lease`

请求：

```json
{
  "request_id": "89dfbca3-c313-4f72-a0c4-7ba89b681727",
  "license_id": "2fd44c80-52ca-4b0a-9636-fd88b7d3cc0e",
  "installation_id": "6af18735-82ae-42f7-bb7f-f8a4387d32f7",
  "features": ["solver"]
}
```

响应：

```json
{ "token": "<base64 canonical signed lease>" }
```

同一 installation 的新 request_id 表示续租并替换旧 lease；相同 request_id 返回完全相同 token。

### POST `/v1/time-ticket`

请求：

```json
{
  "request_id": "f53bec61-611e-4622-9dac-45db17da33f6",
  "license_id": "2fd44c80-52ca-4b0a-9636-fd88b7d3cc0e",
  "installation_id": "6af18735-82ae-42f7-bb7f-f8a4387d32f7"
}
```

响应：

```json
{ "token": "<base64 canonical signed time ticket>" }
```

## 9. 管理 HTTP API

管理 Router 必须位于受控 listener。所有请求包含：

```http
Authorization: Bearer <high-entropy-secret>
```

| 方法与路径 | Body | 作用 |
| --- | --- | --- |
| POST `/admin/v1/entitlements` | entitlement JSON | 注册授权定义 |
| POST `/admin/v1/licenses/{license_id}/revoke` | `{"reason":"..."}` | 撤销并提高 epoch |
| DELETE `/admin/v1/licenses/{license_id}/installations/{installation_id}` | `{"reason":"..."}` | 解绑安装 |
| GET `/admin/v1/audit` | 无 | 返回审计事件 |
| GET `/admin/v1/metrics` | 无 | 返回进程内指标 |
| POST `/admin/v1/backup` | 无 | 在配置目录创建在线备份 |

管理 actor 由 `credential_id` 映射，body 不能指定 actor。备份 API 不接受路径，防止路径穿越或覆盖任意文件。

## 10. HTTP 错误格式

```json
{
  "code": "LEASE_LIMIT",
  "detail": "浮动租约并发数已达上限"
}
```

主要状态映射：

| HTTP | 错误码 |
| --- | --- |
| 400 | INVALID_REQUEST、TOKEN_INVALID、TOKEN_EXPIRED |
| 401 | UNAUTHORIZED |
| 403 | LICENSE_REVOKED、ACTIVATION_REQUIRED、FEATURE_DENIED |
| 404 | UNKNOWN_LICENSE |
| 409 | ACTIVATION_LIMIT、LEASE_LIMIT、TOKEN_REPLAY |
| 413 | PAYLOAD_TOO_LARGE |
| 429 | RATE_LIMITED |
| 500 | INTERNAL |

生产边缘 API 可隐藏 `detail`，但应保留稳定 `code` 和内部关联 ID。

## 11. 离线错误码

| 枚举 | 稳定字符串 | 含义 |
| --- | --- | --- |
| FormatInvalid | LIC_FORMAT_INVALID | 格式/schema/字段错误 |
| SignatureInvalid | LIC_SIGNATURE_INVALID | 签名错误 |
| ProductMismatch | LIC_PRODUCT_MISMATCH | 产品不匹配 |
| NotYetValid | LIC_NOT_YET_VALID | 尚未生效 |
| Expired | LIC_EXPIRED | 已到期 |
| VersionNotAllowed | LIC_VERSION_NOT_ALLOWED | 版本或维护期不允许 |
| MachineMismatch | LIC_MACHINE_MISMATCH | 机器策略失败 |
| FeatureDenied | LIC_FEATURE_DENIED | 功能未授权 |
| TimeRollback | LIC_TIME_ROLLBACK | 时间回拨 |
| OnlineRequired | LIC_ONLINE_REQUIRED | 需要在线决策 |
| KeyRevoked | LIC_KEY_REVOKED | KeyId/状态/generation 不接受 |

## 12. CLI

| 二进制 | 用途 |
| --- | --- |
| `license_keygen` | 生成 32 字节 Ed25519 私钥和公钥 |
| `license_issue` | 早期开发签发，不进入生产包 |
| `license_issue_governed` | 结构化治理签发并生成 receipt |
| `license_verify` | 验证 License |
| `machine_code` | 输出当前机器域分离指纹 |
| `time_anchor_demo` | 演练 DPAPI 时间锚 |
| `sdk_demo` | 演练产品授权集成 |
| `online_demo` | 内存服务端到端流程 |
| `online_server` | 无持久化 HTTP 参考服务 |
| `online_sqlite_server` | SQLite HTTP 参考服务，固定开发 key |
| `online_secure_server` | 外部 key + TLS + 独立管理 listener |
| `online_backup_verify` | 用公钥检查 SQLite 备份 |

完整命令见 [BUILD_AND_TEST.md](BUILD_AND_TEST.md)。
