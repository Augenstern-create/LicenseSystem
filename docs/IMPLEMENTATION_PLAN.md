# License 系统实施计划

本文把《商业软件 License 架构设计方案》转换为可逐项验收的工程任务。实现顺序遵循“先建立离线可信闭环，再增加设备与在线能力”。

每一步的需求基线、实现清单、问题记录和前后同步结果位于 [`steps/`](steps/README.md)。实际编码以对应步骤文档为准；遇到问题时先记录问题和新思路，再继续修改实现。

## 当前基线

- 已有 AES-GCM、ECDSA P-256、RSA-PSS 算法演示。
- 现有签名直接覆盖 JSON 原始字节，没有正式信封、KeyId、公钥状态、严格数据模型或业务授权上下文。
- 现有 `main.rs` 是算法演示，不是可复用的 License SDK。
- AES 不参与 License 防伪；客户端共享密钥不能替代数字签名。

## P0：设计冻结

交付物：

- `LicenseEnvelope`：magic、格式版本、算法、KeyId、规范化 payload 和签名。
- `LicensePayload`：产品、客户、期限、功能、额度、资源范围、机器策略和撤销代际。
- 签名输入：`UTF8("AUGENSTERN-LICENSE-V1\0") || canonical_payload`。
- 默认算法：Ed25519；RSA-PSS 仅作为后续兼容适配器。
- 错误码、输入上限、公钥状态和失败关闭策略。

验收：数据模型和编码规则可由测试向量固定，未知格式/算法/KeyId 必须拒绝。

## P1：离线核心闭环

任务：

1. 实现确定性 CBOR 编解码和规范性复核。
2. 实现 Ed25519 签发、域分离验签和 KeyId 公钥白名单。
3. 校验 schema、产品、时间、版本、机器匹配结果及字段边界。
4. 生成不可变 `AuthorizationContext`，提供 Feature、Limit、ResourceScope 查询。
5. 提供密钥生成、签发和验证 CLI。
6. 建立合法、篡改、错误 KeyId/算法、过期、产品不匹配、尺寸超限等测试。

验收：`cargo test --all-targets`、`cargo clippy --all-targets -- -D warnings` 全部通过；私钥不编译进客户端库。

## P2：产品业务集成

任务：将 `AuthorizationContext` 注入产品，并在算法注册、任务调度、模型加载、设备访问和高价值 API 等关键路径使用授权数据。

验收：不存在可控制全部高价值能力的单一可写 `isLicensed` 布尔值；功能、额度和资源范围均有边界测试。

## P3：机器与时间

任务：实现 Windows 硬件信号采集、归一化/域分离哈希、加权匹配、安装实例 ID、受保护时间锚、回拨检测和宽限状态机。

验收：单个低/中权重硬件变化不误杀；克隆或高可信信号不匹配会拒绝；时间回拨有稳定原因码和恢复路径。

## P4：在线增强

任务：实现激活、短期租约、服务器时间票据、撤销代际、浮动并发、心跳和断网宽限。

验收：席位分配具备原子性，崩溃后可超时回收，旧租约不可重放，离线宽限不会自动无限延长。

当前进度：内存参考服务、HTTP 合约、客户端票据校验、并发状态机以及 SQLite 单节点事务持久化已完成；管理员认证、TLS、监控、备份及灾难恢复尚未完成，详见 `steps/04-online-services.md` 和 `steps/04b-sqlite-persistence.md`。

## P5：签发与发布加固

任务：把生产私钥迁移到 HSM/KMS/隔离签名服务，增加审批和不可变审计，完成密钥轮换、撤销演练、模糊测试、代码签名与运维手册。

验收：开发/测试/生产信任根隔离；生产私钥不可导出到桌面生成器；轮换和泄漏响应演练通过。

当前进度：Key generation/minimum generation、受治理签发与 receipt、解析稳健性、fuzz target、Python 跨语言向量、秘密扫描、release profile 和 Runbook 已完成。正式发布仍被已跟踪历史 RSA 私钥、生产 KMS/HSM、企业审批、代码签名、责任人和真实灾备演练阻塞，详见 `steps/05-hardening-and-release.md`。

## P6：文档化与开发者交付

任务：补齐严格 rustdoc、关键安全函数注释、架构文档、Rust/HTTP/CLI 接口文档、编译测试指南、README 导航、测试函数说明和总体路线图。

验收：严格 rustdoc、Markdown 本地链接、全量测试、Clippy 和跨语言向量全部通过；文档明确保留生产发布阻塞项。

当前进度：已完成，详见 `steps/06-documentation-and-handoff.md`。

## 安全注意事项

仓库当前存在历史演示私钥文件，其中 `.der` 文件曾被 Git 跟踪。它们只能视为已经泄漏的开发测试密钥，不能用于任何生产 License。后续应在确认不再需要历史演示后轮换并从仓库历史中清理。
