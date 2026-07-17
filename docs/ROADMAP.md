# LicenseSystem 后续事项总体路线图

## 1. 当前完成状态

| 阶段 | 状态 | 输出 |
| --- | --- | --- |
| P0 | 完成 | 协议、数据模型、错误模型冻结 |
| P1 | 完成 | Ed25519、规范 CBOR、KeyRing、CLI、固定向量 |
| P2 | 完成 | 虚拟 SDK 深度集成 |
| P3 | 完成 | Windows 机器身份、时间锚、回拨检测 |
| P4.1 | 完成 | 在线内存协议、Lease/TimeTicket、HTTP |
| P4.2 | 完成 | SQLite immediate 事务、重启恢复 |
| P4.3 | 完成 | 管理认证、TLS、限流、指标、备份恢复参考实现 |
| P5 仓库部分 | 完成 | generation、治理签发、receipt、fuzz、跨语言、发布门禁 |
| P5 生产发布 | 阻塞 | KMS/HSM、企业审批、代码签名、历史秘密、真实灾备 |
| P6 | 进行中 | 注释、架构、接口、编译测试与交付文档 |

## 2. 最高优先级发布阻塞

### 2.1 历史私钥

`keys/rsa_private.der` 已被 Git 跟踪，必须视为泄漏。

需要：

1. 确认任何环境均不信任对应公钥；
2. 仓库所有者批准历史重写；
3. 按 Runbook 使用 git-filter-repo/BFG；
4. 扫描所有 refs、fork、release asset、CI artifact 和备份；
5. 通知协作者重新克隆。

未经批准不得自动执行历史重写。

### 2.2 生产 KMS/HSM

当前 Rust API 接受 `SigningKey`，适合测试和隔离参考环境。生产应：

- 定义 `StructuredLicenseSigner`/远程签名适配器；
- KMS/HSM 内部执行 Ed25519；
- 私钥不可导出；
- request_id、审批身份、payload hash、KeyId、generation 进入不可变审计；
- KMS 不可用时停止新签发，不降级到桌面 key。

### 2.3 企业身份与审批

`requested_by`/`approved_by` 当前是受控字符串，必须替换为：

- OIDC/mTLS 认证主体；
- RBAC；
- 双人审批工作流；
- 短期凭据和无停机轮换；
- 不可变审计存储。

### 2.4 代码签名与供应链

需要：

- 组织代码签名证书；
- 受保护 CI runner；
- 锁定工具链和依赖审计；
- SBOM；
- 制品 SHA-256 和签名；
- 发布渠道强制验证；
- 可复现构建评估。

## 3. 后续代码事项

### 3.1 客户端 replay 持久化

把 `OnlineTokenVerifier` 的最新 Lease/TimeTicket 顺序状态与 P3 DPAPI 时间锚统一保存，防止客户端重启后接受旧 token。

验收：

- 原子状态；
- DPAPI/HMAC 鉴权；
- 大小限制和 symlink 拒绝；
- 删除状态被识别为新安装并触发在线恢复。

### 3.2 PostgreSQL/多节点存储

抽象当前 SQLite service storage：

- entitlement/activation/lease/idempotency/audit repository；
- PostgreSQL `SERIALIZABLE` 或显式行锁；
- request_id 唯一约束；
- 多实例并发和故障注入；
- schema migration 工具；
- 连接池、超时和可观测性。

### 3.3 管理身份升级

替换单 Bearer token：

- mTLS 或 OIDC；
- 多 credential；
- 权限分级：entitlement、revoke、audit、backup；
- 双人敏感操作；
- token/certificate rotation。

### 3.4 可观测性

当前指标为进程内 JSON。后续：

- Prometheus/OpenTelemetry；
- latency histogram；
- SQLite busy、事务失败、签名失败；
- 按错误码分类但不泄漏完整 LicenseId；
- trace/request correlation id；
- 告警规则自动化。

### 3.5 协议演进

未来 v2 必须：

- 新 magic/version 或明确字段版本；
- 新 domain separator；
- 保持 v1 测试向量；
- 双版本客户端迁移窗口；
- 规范 CBOR 跨语言向量；
- downgrade 测试。

### 3.6 错误最小披露

参考 HTTP 返回 `detail`。生产边缘应：

- 对外仅稳定 code 和 correlation id；
- 内部日志保存受控 detail；
- LicenseId 只记录后缀；
- 不记录 token、机器原始值、customer_id 或 body。

## 4. 质量与安全测试

### 持续 fuzz

- nightly CI 每次至少 5 分钟；
- 定期长时 campaign；
- corpus 去敏；
- crash 固化为普通回归测试；
- 覆盖 offline envelope/payload、online token 和管理 JSON 边界。

### 跨语言

当前有 Python verifier。后续增加：

- 一个服务端语言的签发器；
- 一个客户端语言的验证器；
- v1/v2 双版本向量；
- canonical CBOR 键排序、整数最短编码和重复键负向向量。

### 故障注入

- SQLite/PostgreSQL busy、磁盘满、只读目录；
- 事务提交前崩溃；
- 备份中并发写入；
- TLS 证书过期/不匹配；
- KMS 超时；
- UTC 跳变；
- 多进程时间锚竞争。

## 5. 产品与客户流程

需要产品、法务、销售和支持确认：

- 最长离线 License 生命周期；
- 客户端支持周期；
- 旧 Key 移除条件；
- 离线撤销边界；
- 硬件迁移次数和机器阈值；
- 误撤销补偿；
- 解绑、离线续期和客户迁移 SLA；
- 数据保留和审计合规要求。

## 6. 运维与灾备

参考 Runbook 已存在，但生产还需：

- 自动在线备份调度；
- 加密不可变异地存储；
- 定期恢复演练；
- 批准的 RPO/RTO；
- 多节点数据库与故障转移；
- 证书、磁盘、备份和 5xx 告警；
- 24×7 责任人和值班升级路径。

## 7. 建议实施顺序

1. 历史私钥撤销确认和清理审批；
2. KMS/HSM 签名适配器；
3. 企业身份与不可变审批审计；
4. 客户端 replay 持久化；
5. PostgreSQL 和多节点服务；
6. OpenTelemetry/Prometheus 与告警；
7. 代码签名、SBOM 和受保护发布流水线；
8. 真实备份恢复、泄漏、误撤销和 KMS 故障演练；
9. 正式发布评审和签字。

## 8. 责任矩阵

| 事项 | 建议责任人 |
| --- | --- |
| License 协议与客户端 | 核心研发/安全研发 |
| KMS/HSM 与密钥生命周期 | 安全平台 |
| 在线数据库与高可用 | 后端/DBA/SRE |
| 企业身份与审批 | IAM/安全平台 |
| 客户策略与支持周期 | 产品/法务/客户支持 |
| 代码签名与发布 | 发布工程/供应链安全 |
| 监控、备份与灾备 | SRE/运维 |
| 历史清理授权 | 仓库所有者/安全负责人 |

## 9. 发布准入

满足 [发布安全检查表](release-checklist.md) 全部必选项之前，状态保持“不可生产发布”。仓库内测试全部通过不等于组织和基础设施已经满足生产要求。
