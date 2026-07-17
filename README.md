# LicenseSystem

Rust 商业软件 License 系统参考实现，依据《商业软件 License 架构设计方案》逐步实现。

项目覆盖离线签发与验签、产品授权集成、Windows 机器身份与时间锚、在线激活/租约/撤销、SQLite 持久化、TLS 管理面、备份恢复、签发治理和发布门禁。

> 当前状态：协议、单节点参考实现、测试和仓库内加固已经完成；这是一套开发与架构参考实现，不可把仓库内 Demo 密钥或命令直接用于生产。生产发布仍需要 KMS/HSM、企业审批、代码签名、集中监控和真实灾备等外部能力。

## 新用户快速开始（Windows PowerShell）

本节从一台没有 Rust 开发环境的 Windows 电脑开始，依次完成：

1. 安装环境；
2. 获取代码；
3. 编译项目；
4. 生成 Ed25519 开发密钥；
5. 签发 License；
6. 验证 License；
7. 运行虚拟图像 SDK Demo。

基础流程只需要 Git、MSVC C++ Build Tools、Rust stable 和 PowerShell，不需要 Python、OpenSSL、数据库服务或云服务。

### 第 1 步：安装 Git

从 [Git for Windows 官方网站](https://git-scm.com/download/win)下载安装，安装过程使用默认选项即可。也可以在支持 WinGet 的 PowerShell 中执行：

```powershell
winget install --id Git.Git -e --source winget
```

安装完成后关闭并重新打开 PowerShell，然后确认：

```powershell
git --version
```

如果系统提示找不到 `git`，先重新打开终端；仍然找不到时，检查 Git 安装目录是否已加入 `PATH`。

### 第 2 步：安装 MSVC C++ Build Tools

Windows 上的 Rust MSVC 工具链需要 Microsoft 链接器和 Windows SDK。安装 Visual Studio Community 或独立 Build Tools 均可：

1. 打开 [Microsoft C++ Build Tools 安装说明](https://learn.microsoft.com/en-us/cpp/build/vscpp-step-0-installation?view=msvc-170)；
2. 启动 Visual Studio Installer；
3. 勾选 **使用 C++ 的桌面开发（Desktop development with C++）**；
4. 保留该工作负载默认选择的 MSVC x64/x86 Build Tools 和 Windows SDK；
5. 完成安装并重新打开 PowerShell。

不需要创建 Visual Studio 工程，本项目仍然使用 Cargo 编译。

### 第 3 步：安装 Rust stable

从 [Rust 官方安装页](https://www.rust-lang.org/tools/install)下载并运行 `rustup-init.exe`。选择默认安装即可；本项目使用 `stable-x86_64-pc-windows-msvc` 工具链。

安装完成后关闭并重新打开 PowerShell，执行：

```powershell
rustup default stable-x86_64-pc-windows-msvc
rustup update stable
rustc --version
cargo --version
```

本项目使用 Rust 2024 edition，需要 Rust 1.85 或更高版本，建议始终使用当前 stable。

如果 Cargo 已安装但不在 `PATH`，可以在当前 PowerShell 临时补充：

```powershell
$env:Path += ";$env:USERPROFILE\.cargo\bin"
cargo --version
```

### 第 4 步：获取代码并进入项目目录

选择一个用于保存代码的目录：

```powershell
cd <你用于保存代码的目录>
git clone https://github.com/Augenstern-create/LicenseSystem.git
cd LicenseSystem
```

如果代码已经通过压缩包或其他方式取得，只需进入包含 `Cargo.toml` 的项目根目录。确认位置：

```powershell
Get-Location
Test-Path Cargo.toml
```

`Test-Path Cargo.toml` 应输出 `True`。后续所有命令都在这个项目根目录执行。

### 第 5 步：下载依赖并编译

首次执行时 Cargo 会从 crates.io 下载 Rust 依赖，需要能访问互联网：

```powershell
cargo check --all-targets
cargo build --all-targets
```

两条命令最后都应显示 `Finished`。生成的 Debug 可执行文件位于 `target\debug\`。

在 Windows 上构建 `online_secure_server` 时可能看到类似下面的 warning：

```text
linker stdout: 正在创建库 ...online_secure_server.lib 和对象 ...online_secure_server.exp
```

这是 MSVC 为可执行文件创建导入库时输出的信息；只要命令最终显示 `Finished`，就不是编译失败。

常见编译问题：

- `cargo` 不是命令：重新打开 PowerShell，或把 `%USERPROFILE%\.cargo\bin` 加入 `PATH`；
- `link.exe not found`：返回第 2 步安装“使用 C++ 的桌面开发”和 Windows SDK；
- 下载 crates.io 超时：检查代理、DNS 或公司网络策略后重试；Cargo 会复用已下载的缓存。

### 第 6 步：生成开发密钥

执行：

```powershell
cargo run --bin license_keygen -- `
  keys/quickstart-private.key keys/quickstart-public.key
```

成功后检查文件：

```powershell
Get-Item keys/quickstart-private.key, keys/quickstart-public.key
```

两个文件都应为 32 字节：

- `quickstart-private.key`：Ed25519 私钥，只能位于签发环境；
- `quickstart-public.key`：Ed25519 公钥，可随客户端或 SDK 分发。

这些文件只用于本地演示。不要提交私钥，也不要在生产环境使用本教程生成的开发密钥。

### 第 7 步：签发开发 License

仓库已经提供可直接使用的 Payload：`licenses/payload.example.json`。使用刚生成的私钥签发：

```powershell
cargo run --bin license_issue -- `
  licenses/payload.example.json `
  keys/quickstart-private.key quickstart-2026 `
  licenses/quickstart.lic
```

成功输出包含：

```text
License 签发成功
LicenseId: ...
KeyId: quickstart-2026
输出: licenses/quickstart.lic
```

参数含义依次为：Payload JSON、Ed25519 私钥、KeyId 和 License 输出路径。KeyId 是密钥的逻辑标识，签发和验证时必须一致。

`license_issue` 是便于理解流程的开发 CLI，不进入生产发布包；生产签发应使用后文的治理入口和隔离密钥设施。

### 第 8 步：验证 License

使用对应公钥、相同 KeyId 和目标产品 ID 验证：

```powershell
cargo run --bin license_verify -- `
  licenses/quickstart.lic `
  keys/quickstart-public.key quickstart-2026 image-sdk
```

成功时应看到：

```text
License 验证成功
ProductId: image-sdk
Edition: enterprise
CustomerId: CUST-10086
```

验证失败时优先检查：

- 私钥和公钥是否来自同一次 `license_keygen`；
- 签发与验证使用的 KeyId 是否完全相同；
- 产品 ID 是否为示例 Payload 中的 `image-sdk`；
- License 或 Payload 是否被手工修改。

### 第 9 步：运行虚拟图像 SDK Demo

使用已经验证的 License 启动 Demo：

```powershell
cargo run --bin sdk_demo -- `
  licenses/quickstart.lic `
  keys/quickstart-public.key quickstart-2026 `
  image-sdk M001 CAM-001
```

`M001` 和 `CAM-001` 都包含在示例 License 的授权范围内。Demo 会把授权结果绑定到实际业务路径，演示：

- GPU、DeepZoom 和 Batch 算法功能开关；
- `max_parallel_jobs` 并行任务限制；
- 模型 ID 与设备 ID 的资源范围；
- 不依赖单一可写 `isLicensed` 布尔值的授权上下文。

至此，最小离线流程已经完成：

```text
Payload JSON → 私钥签发 → .lic 文件 → 公钥验证 → SDK 业务授权
```

### 重复运行快速开始

密钥和 License 输出默认拒绝覆盖，这是为了避免误覆盖密钥或审计产物。如果只想重新运行本教程，可以删除本教程专用文件后从第 6 步重新开始：

```powershell
Remove-Item keys/quickstart-private.key, keys/quickstart-public.key, licenses/quickstart.lic `
  -ErrorAction SilentlyContinue
```

不要把这条命令替换成删除整个 `keys` 或 `licenses` 目录。

## 进阶：治理签发与 receipt

治理签发的第一个参数不是普通 Payload，而是包含请求人和审批人的结构化请求。下面从现有示例 Payload 生成一个 30 天、非高风险的开发请求：

```powershell
$payload = Get-Content licenses/payload.example.json -Raw | ConvertFrom-Json
$issuedAt = [DateTimeOffset]::UtcNow

$payload.license_id = [guid]::NewGuid().ToString()
$payload.issued_at = $issuedAt.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
$payload.expires_at = $issuedAt.AddDays(30).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
$payload.maintenance_until = $payload.expires_at

$request = [ordered]@{
  payload      = $payload
  requested_by = "quickstart-issuer"
  approved_by  = @()
}

$request | ConvertTo-Json -Depth 20 |
  Set-Content licenses/quickstart-request.json -Encoding utf8
```

使用快速开始中已经生成的私钥进行治理签发：

```powershell
cargo run --bin license_issue_governed -- `
  licenses/quickstart-request.json `
  keys/quickstart-private.key quickstart-2026 1 `
  licenses/quickstart-governed.lic `
  licenses/quickstart-governed-receipt.json
```

验证治理签发的 License：

```powershell
cargo run --bin license_verify -- `
  licenses/quickstart-governed.lic `
  keys/quickstart-public.key quickstart-2026 image-sdk
```

治理入口执行 ACTIVE key 和 generation 检查，并生成包含 License SHA-256 的 receipt。永久 License、有效期超过 366 天或任一额度超过 10000 时，`approved_by` 必须包含至少两个不同且不是 `requested_by` 的审批者，例如：

```json
"approved_by": ["security-approver", "business-approver"]
```

治理 CLI 同样拒绝覆盖输出。重复演练时请使用新文件名，或只删除上述 `quickstart-governed*` 教程产物。

## 其他可运行 Demo

### Windows 机器身份

```powershell
cargo run --bin machine_code -- image-sdk
```

输出只包含产品域分离 SHA-256 指纹、权重和可信等级，不输出原始机器值。

### 时间锚

```powershell
cargo run --bin time_anchor_demo -- `
  target/quickstart-anchor.state `
  2fd44c80-52ca-4b0a-9636-fd88b7d3cc0e
```

Windows 使用 DPAPI 绑定当前用户。默认允许 6 小时小幅校时，超过容忍范围返回 `LIC_TIME_ROLLBACK`。

### 在线内存端到端 Demo

```powershell
cargo run --bin online_demo
```

流程为 entitlement → activation → Lease/TimeTicket → 本地验签 → revoke，不需要外部数据库。

### SQLite 参考 Server

```powershell
cargo run --bin online_sqlite_server -- `
  target/online-demo.sqlite 127.0.0.1:3000
```

首次启动会输出 `license_id`。重启时把该 ID 作为第三个参数传回，可复用 entitlement 和持久化状态。使用 `Ctrl+C` 停止服务。

TLS 安全 Server、管理 API 和备份恢复需要额外证书与运维配置，参见 [编译与测试指南](docs/BUILD_AND_TEST.md)和[接口文档](docs/API.md)。

## 测试与质量检查

运行全部测试：

```powershell
cargo test --all-targets
```

运行严格 Clippy：

```powershell
rustup component add clippy
cargo clippy --all-targets -- -D warnings
```

运行单个测试文件：

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

生成严格 rustdoc：

```powershell
$env:RUSTDOCFLAGS = '-D missing-docs -D rustdoc::broken-intra-doc-links'
cargo doc --no-deps --lib
Remove-Item Env:RUSTDOCFLAGS
```

测试文件、主要测试函数和临时文件位置详见[编译与测试指南](docs/BUILD_AND_TEST.md#12-测试文件与主要函数)。

## 可选开发工具

以下工具不是快速开始必需项：

- Python 3 与 `cryptography`：运行独立跨语言验证；
- Rust nightly 与 `cargo-fuzz`：运行模糊测试；
- OpenSSL：手工生成或检查 TLS 测试证书。

Python 跨语言验证：

```powershell
python -m pip install cryptography
python scripts/verify_license_vector.py
```

检查 fuzz target 是否可编译：

```powershell
cargo check --manifest-path fuzz/Cargo.toml
```

## Release 编译与发布检查

编译主要 Release 产物：

```powershell
cargo build --release --lib `
  --bin online_secure_server `
  --bin online_backup_verify `
  --bin license_issue_governed
```

仓库检查：

```powershell
./scripts/release_secret_audit.ps1 -AuditOnly
./scripts/check_markdown_links.ps1
git diff --check
```

正式秘密审计：

```powershell
./scripts/release_secret_audit.ps1
```

当前正式模式会因 Git 跟踪的 `keys/rsa_private.der` 返回退出码 2。这是已记录的发布阻塞项；未经仓库所有者审批，本项目不会删除文件或重写 Git 历史。

## 项目模块

| 模块 | 说明 |
| --- | --- |
| `license` | 离线 Payload、确定性 CBOR、签发、验签、KeyRing 和治理签发 |
| `demo_sdk` | 虚拟图像 SDK，演示 feature、limit 和 resource scope 的业务深度绑定 |
| `machine` | Windows 机器信号采集、归一化、哈希与加权匹配 |
| `time_anchor` | HMAC/DPAPI 受保护本地状态、原子更新与时间回拨检测 |
| `online` | 激活、Lease、TimeTicket、SQLite、HTTP、管理、限流、指标和备份 |
| `src/bin` | 密钥、签发、验证、Demo、Server 和备份命令行入口 |

`src/aes.rs`、`src/ecdsa.rs`、`src/rsa.rs` 是历史算法演示，不是正式 License 入口。

## 文档导航

- [项目架构](docs/ARCHITECTURE.md)
- [Rust、HTTP 与 CLI 接口](docs/API.md)
- [编译、运行与测试](docs/BUILD_AND_TEST.md)
- [后续事项总体路线图](docs/ROADMAP.md)
- [分步实施记录](docs/steps/README.md)
- [发布安全检查表](docs/release-checklist.md)
- [在线运维与恢复 Runbook](docs/runbooks/online-operations.md)
- [密钥轮换与泄漏响应](docs/runbooks/key-rotation-and-incident.md)

## 当前生产限制与安全提示

- 仓库内历史私钥、测试 seed 和 Demo 固定 key 全部视为公开；
- 客户端只能分发公钥，生产私钥必须进入 KMS/HSM 或隔离签名系统；
- 管理认证参考实现仍是单高熵 Bearer token，SQLite 仍是单节点；
- 指标是进程内累计，客户端 replay cache 尚未持久化；
- 尚无企业审批、代码签名、SBOM、集中监控和真实灾备证据；
- 不记录完整 License、管理员 token、原始机器标识或完整 customer_id；
- 完全离线 License 无法实时撤销，该边界需要产品和合同共同约束；
- 测试通过不等于生产治理和基础设施已经完成。

后续顺序、责任矩阵和发布准入见[总体路线图](docs/ROADMAP.md)。
