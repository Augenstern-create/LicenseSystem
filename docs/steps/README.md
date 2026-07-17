# License 系统分步实施索引

## 执行规则

每个步骤必须遵循同一闭环：

1. **实现前确认**：核对设计方案、上一步输出、范围、接口、风险和验收命令，在步骤文档中记录确认结果。
2. **按清单实现**：只实现当前步骤已列出的事项；超出范围的想法记录到后续步骤，不隐式扩张范围。
3. **问题先入文档**：遇到编译、设计、环境或验证问题，先写入当前步骤的“问题与新思路”，包括现象、影响、原因、新方案和验证办法，然后再修改代码。
4. **实现后同步**：逐项对照需求与实际文件，记录完成、偏差、遗留项及验证证据。
5. **进入下一步**：只有当前步骤的硬性验收全部通过，或偏差被明确接受并记录，才把下一步骤设为进行中。

## 步骤状态

| 步骤 | 文档 | 状态 | 主要输出 |
| --- | --- | --- | --- |
| P0 | [00-design-freeze.md](00-design-freeze.md) | 已完成 | 数据模型、信封、签名输入、模块边界、错误模型 |
| P1 | [01-offline-core.md](01-offline-core.md) | 已完成 | Ed25519 + CBOR 核心库、CLI、测试向量 |
| P2 | [02-product-integration.md](02-product-integration.md) | 已完成 | 虚拟图像 SDK 的 AuthorizationContext 业务深度绑定 |
| P3 | [03-machine-and-time.md](03-machine-and-time.md) | 已完成 | Windows 机器指纹、安装实例、时间锚与回拨检测 |
| P4.1 | [04-online-services.md](04-online-services.md) | 已完成 | 在线内存参考协议、票据、HTTP 与并发状态机 |
| P4.2 | [04b-sqlite-persistence.md](04b-sqlite-persistence.md) | 已完成 | SQLite 事务持久化、签名身份绑定与重启恢复 |
| P4.3 | [04c-security-operations.md](04c-security-operations.md) | 已完成 | 管理认证、TLS、限流、指标、备份与恢复参考实现 |
| P5 | [05-hardening-and-release.md](05-hardening-and-release.md) | 受阻 | 仓库内加固完成；生产 KMS/审批/签名/历史私钥/灾备证据待外部完成 |
| P6 | [06-documentation-and-handoff.md](06-documentation-and-handoff.md) | 已完成 | 代码注释、架构、接口、编译测试与后续路线文档 |

## 状态定义

- **未开始**：只有规划，不允许开始编码。
- **进行中**：已完成实现前确认，正在实现或验证。
- **已完成**：实现后同步表已填写，所有硬性验收通过。
- **受阻**：问题已记录，但当前条件下无法满足硬性验收。
