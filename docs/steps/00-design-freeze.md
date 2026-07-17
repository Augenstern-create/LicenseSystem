# P0：设计冻结

## 目标

把架构方案转换为 Rust 工程能够直接实现和测试的稳定契约，避免在密码学、序列化和业务校验之间反复变更。

## 实现前确认

- 来源：`商业软件License架构设计方案.docx` 的第 4～6、10、13～16 节。
- 当前代码只有 AES、ECDSA、RSA 算法演示及直接对 JSON 文件字节签名的工具。
- 客户端正式链路不得包含私钥或共享 AES 密钥。
- 状态：已确认，允许进入设计冻结。

## 详细事项

### 1. 信封契约

- 文件上限：64 KiB。
- 二进制格式：确定性 CBOR。
- 字段：magic、format_version、algorithm、key_id、payload、signature。
- magic：`ALIC`。
- format_version：`1`。
- 默认算法：`Ed25519`；算法只能来自代码白名单。
- 未知字段、未知版本、乱序/非规范编码、尾随数据全部拒绝。

### 2. 签名契约

- 签名输入：`UTF8("AUGENSTERN-LICENSE-V1\0") || canonical_payload`。
- 签名只覆盖规范化 payload 原始字节，不对解析后重新生成的 JSON 签名。
- 验证方只根据本地 KeyRing 的 KeyId 选择公钥。
- Key 状态：Active、VerifyOnly 可验证；Revoked、Retired 拒绝。

### 3. Payload 契约

- 固定 schema_version、UUID license_id、product_id、edition、customer_id。
- UTC 时间字段：issued_at、not_before、expires_at、maintenance_until。
- 许可类型：trial、node_locked、subscription、floating、site。
- 业务授权：features、limits、resource_scope。
- 演进字段：min/max_app_version、revocation_epoch、custom。
- 机器策略在 P1 中建模和消费外部匹配结果，硬件采集/计算放入 P3。

### 4. CBOR 规范性

- 顶层对象使用递增整数键，避免文本字段名和实现语言字段顺序造成差异。
- 动态 Map 的文本键按其完整 CBOR 编码“长度优先、再逐字节”排序。
- 解码后必须重新编码并与原字节比较；不一致即 `LIC_FORMAT_INVALID`。
- 不允许不定长 Map/Array。

### 5. 模块边界

- `model`：数据模型和不可变授权上下文。
- `cbor`：唯一规范编码/严格解码实现。
- `signing`：Issuer 侧签发入口。
- `validation`：客户端验证顺序和 KeyRing。
- `error`：稳定错误码与内部详细原因。

## 验收标准

- [x] 设计字段和格式均有明确版本。
- [x] 算法、KeyId 和信任根不受 License 文件控制。
- [x] 签名输入包含域分离。
- [x] AuthorizationContext 与原始 License 文件解耦。
- [x] P1、P2、P3 的职责边界明确。

## 问题与新思路

### DOCX 无法完成逐页视觉渲染

- 现象：文档技能的 `render_docx.py` 报 `WinError 2`，环境缺少 LibreOffice/soffice。
- 影响：无法用页面 PNG 校验版面，页码引用不可靠。
- 处理：按文档技能允许的回退方案，使用 `python-docx` 完整提取标题、段落和 20 个表格；本项目只读取设计内容，不修改原 DOCX。
- 验证：已提取第 1～18 节及附录中的字段表、流程、错误码、路线图和测试清单。

### Canonical CBOR 的动态 Map 排序

- 原思路：直接使用 Rust `BTreeMap` 的文本字典序。
- 问题：CBOR 确定性编码要求比较编码后的键，单纯字符串字典序不足以覆盖不同长度的键。
- 新思路：先编码每个文本键，再按编码长度和字节序排序；验证时重编码比较。
- 验证：P1 增加重复签发字节完全一致及非规范输入拒绝测试。

## 实现后同步

| 设计项 | 实际结果 | 同步状态 |
| --- | --- | --- |
| 格式/版本/域分离 | 已写入 `src/license/mod.rs` 常量及 P1 设计 | 一致 |
| 模块边界 | 已建立 `src/license/{model,cbor,signing,validation,error}.rs` | 一致 |
| Payload 与错误码 | 已建立类型，详细验证在 P1 完成 | 一致 |
| 后续步骤边界 | 已拆分 P2～P5 文档 | 一致 |

结论：P0 完成，P1 可以继续。
