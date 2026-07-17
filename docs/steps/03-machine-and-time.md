# P3：机器指纹与可信时间

## 目标

在 Windows 离线环境中提供可解释、可迁移的机器绑定，并通过受保护时间锚提高系统时间回拨成本。

## 实现前确认（进入本步骤时填写）

- [x] P2 已完成；虚拟 SDK 将作为 node_locked/离线时间策略的集成对象。
- [x] 当前目标平台为 Windows 桌面环境；本步骤提供可测试的跨平台核心，Windows 采集器和 DPAPI 实现使用 `cfg(windows)` 隔离。服务账户、漫游用户和虚拟机模板属于部署配置，不能由库自动猜测。
- [x] 原始硬件标识只在进程内短暂存在；License 和常规日志只使用产品域分离 SHA-256 指纹。真实产品上线前仍需补充隐私告知、解绑和迁移支持流程。
- [x] Windows 默认状态保护采用 DPAPI 当前用户范围；同时提供 HMAC 状态保护器用于测试或“安装密钥已经由 TPM/DPAPI 保护”的宿主。TPM 证明采集留作增强项，不伪造 TPM 能力。

状态：实现前确认、编码、实机演练和实现后验收均已完成。

## 详细实现事项

### 机器指纹

1. [x] 定义 `MachineSignalCollector`、信号类别、稳定性权重和高可信标记；测试可注入虚拟信号。
2. [x] Windows 采集 MachineGuid、Raw SMBIOS System UUID、系统卷序列号、CPU 标识；缺失项不使用空值占位。
3. [x] 统一去空白、大小写、分隔符和已知无效占位值；相同语义值必须得到相同规范结果。
4. [x] 使用 `AUGENSTERN-MACHINE-V1\0 + length-prefixed(product_id/kind/value)` 做 SHA-256，不持久化原始值。
5. [x] 把 P1 的调用者自报 `MachineMatch` 改为 `MachineIdentity` 组件输入；验证器根据签名内 fingerprints、权重和高可信规则自行计分。
6. [x] 输出可解释但不泄露原始标识的匹配报告，用于客服迁移诊断。
7. [x] 增加容错测试：一个中权重信号变化仍可通过；高可信信号缺失或分数不足拒绝；重复组件不能重复计分。

### 时间锚

1. [x] 建立随机 `installation_id`，保存 schema、last_seen_utc、last_monotonic_ms 和最近 license_id。
2. [x] 定义 `StateProtector`；实现 HMAC-SHA256 完整性保护和 Windows DPAPI 当前用户保护。
3. [x] 状态文件限制大小、拒绝符号链接、先写临时文件并 flush/sync，再使用原子替换；Windows 独占事务锁防止多进程丢失更新。
4. [x] 默认允许 6 小时向后校时；超过容差返回 `LIC_TIME_ROLLBACK` 且不覆盖旧锚。
5. [x] 小幅回调成功时保持 `last_seen_utc` 单调不减；重启导致 monotonic 归零时只依赖 UTC 锚。
6. [x] 区分首次创建、正常前进、小幅回调和回拨拒绝；损坏/鉴权失败必须失败关闭。
7. [x] 明确限制：完全离线且所有本地状态被删除时无法单独阻止重置，后续用冗余位置/激活记录增强。

## 验收标准

- 换一个中低权重部件不误杀；高可信信号全部不匹配时拒绝。
- 相同硬件规范化结果稳定，虚拟机克隆场景有明确策略。
- 时间锚被编辑时 MAC 失败；明显回拨稳定检测；正常校时不误报。
- 所有原始硬件敏感值不进入 License、常规日志或签发审计。
- Windows 集成测试及故障注入测试通过。

## 预期文件

- `src/machine/{mod,normalize,windows}.rs`：机器信号、指纹与 Windows 采集。
- `src/time_anchor/{mod,protector,store}.rs`：受保护状态、原子存储和回拨策略。
- `src/bin/machine_code.rs`：输出可交给签发方的哈希指纹摘要。
- `src/bin/time_anchor_demo.rs`：DPAPI 时间锚演练。
- `tests/machine_identity.rs`、`tests/time_anchor.rs`：跨平台确定性与故障测试。

## 问题与新思路

### P1 的机器匹配输入信任边界过宽

- 现象：`ValidationInput` 当前接受调用者直接构造的 `MachineMatch { score, high_confidence_match }`。
- 影响：产品接入方可以在不提供任何机器信号的情况下自报通过；也无法由核心库解释哪些组件匹配。
- 原因：P1 只为 P3 预留了最终结果，没有冻结机器身份组件接口。
- 新思路：替换为不可含原始硬件值的 `MachineIdentityComponent { fingerprint, weight, high_confidence }`；验证器与签名内 policy fingerprints 求交集并自行计分。
- 兼容影响：这是 0.1.0 未发布 API 的有意调整；同步更新 P1 测试和 P3 文档，不保留不安全的旧入口。
- 验证办法：测试调用者无法直接传入分数，重复 fingerprint 只计一次，阈值与高可信条件均由验证器得出。

### 完全离线删除状态的物理边界

- 现象：攻击者若拥有管理员权限并删除所有本地时间锚和安装身份，单个本地文件无法判断这是首次安装还是状态重置。
- 影响：时间锚只能提高回拨/编辑成本，不能承诺绝对防重装。
- 新思路：本步骤保证状态鉴权、原子更新和失败关闭；P4 通过激活记录/时间票据增强，真实 Windows 产品可在 ProgramData 与注册表保存冗余密封副本。
- 验证办法：篡改状态必须拒绝；显式“无状态首次创建”结果必须对上层可见，不能伪装成已有可信历史。

### 首轮测试通过但存在一个编译 warning

- 现象：36 个测试全部通过，包括 Windows DPAPI 往返、篡改、UTC/单调时钟回拨；`store.rs` 读取文件变量被标记为不需要 `mut`。
- 影响：功能无误，但不满足严格 Clippy 零 warning 质量门。
- 新思路：移除多余可变性，不使用 `allow` 绕过；随后运行 `clippy --all-targets -- -D warnings`。
- 验证办法：严格 Clippy 必须通过，并再次运行全部测试。

### 真实 Windows 机器缺少注册表 SystemUUID，无法满足高可信条件

- 现象：`machine_code image-sdk` 只采集到 CPU(10)、MachineGuid(20)、系统卷(15)，总分 45 且全部为非高可信；注册表 BIOS 路径没有 `SystemUUID`。
- 影响：当前实现签发的 node_locked License 无法在这台真实机器上满足“至少一个高可信信号”，即使所有可采信号都一致。
- 原因：`SystemUUID` 不是所有 Windows/固件都会投影到该注册表值，不能把它当作主要 SMBIOS 获取方式。
- 新思路：使用 Windows `GetSystemFirmwareTable('RSMB')` 读取 Raw SMBIOS，严格遍历结构并提取 Type 1 UUID；注册表 `SystemUUID` 只作为回退。解析器必须有长度检查并拒绝全 0/全 FF UUID。
- 验证办法：增加原始 SMBIOS Type 1 解析测试；在真实机器重新运行 `machine_code`，应出现 `smbios_uuid` 高可信组件，或明确记录固件本身未提供有效 UUID。
- 二次诊断：WMI 可读取 UUID，但 Raw SMBIOS API 仍无结果。根因是 Windows 文档的多字符 provider 常量 `'RSMB'` 应按大端字符数值构造，初版误用了 `u32::from_le_bytes`，实际查询了错误 provider。改为 `from_be_bytes` 后再次实机验证。

### 原子替换不能单独防止多进程丢失更新

- 现象：状态文件写入是原子的，但两个 SDK 进程可能同时读取旧锚；时间较早的进程若最后替换，会覆盖另一个进程刚写入的更晚锚。
- 影响：多实例运行时 `last_seen_utc` 可能倒退，削弱回拨检测。
- 原因：原子替换只保证单次文件完整，不提供“读取 → 判断 → 写入”事务互斥。
- 新思路：Windows 在同目录使用稳定 `.lock` 文件并以 `share_mode(0)` 持有独占句柄，覆盖整个 observe 事务；锁竞争时返回 `Busy` 并失败关闭，不做无锁重试或覆盖。
- 验证办法：测试先持有独占锁，再调用 `observe`，必须返回 Busy；正常连续观察仍保持相同 installation_id。
- 质量检查补充：锁竞争测试通过，但 Clippy 要求创建锁文件时显式声明 truncate 语义。锁文件不存放状态，因此实现和测试均使用 `.truncate(false)`，不依赖默认行为。

### 虚拟机克隆可能复制全部软件可见标识

- 边界：如果虚拟机模板同时复制 SMBIOS UUID、系统卷、CPU 描述和 MachineGuid，纯软件指纹可能把克隆识别为原机器。
- 策略：本步骤不虚构“不可克隆”能力；高价值虚拟化部署应使用 TPM/设备证明，或在 P4 使用 installation_id 在线激活、设备配额和克隆检测。客服迁移流程必须允许合法 VM 恢复。

## 实现后同步

| 需求项 | 实际实现与结果 | 同步状态 |
| --- | --- | --- |
| Windows 信号 | Raw SMBIOS Type 1 UUID(30/高可信)、MachineGuid(20)、系统卷(15)、CPU(10)；TPM 类型预留 50/高可信 | 一致 |
| 实机采集 | 当前 Windows 机器得到 4 个组件、总分 75、包含 SMBIOS 高可信；无原始标识输出 | 一致 |
| 规范化/隐私 | 分隔符与大小写归一、占位符拒绝、产品域分离 SHA-256；License 只保存 fingerprint | 一致 |
| 核心匹配 | `ValidationInput.machine_identity` 替代调用者自报分数，验证器去重类别并自行计算报告 | 一致 |
| 容错与克隆 | 权重/高可信/重复计分测试通过；VM 全量克隆风险明确转交 TPM/P4 激活 | 有记录的物理边界 |
| 状态保护 | HMAC-SHA256 保护器和 Windows DPAPI 当前用户保护器；DPAPI 实机往返通过 | 一致 |
| 时间策略 | UTC + GetTickCount64、6 小时容差、last_seen 单调不减、回拨返回 `LIC_TIME_ROLLBACK` | 一致 |
| 存储安全 | 64 KiB 上限、符号链接拒绝、临时文件 sync + MoveFileEx 原子替换、Windows 独占事务锁 | 一致 |
| SDK 集成 | `license_verify`/`sdk_demo` 自动采集机器身份；`sdk_demo` 可选 DPAPI 时间锚后才启动 SDK | 一致 |
| CLI 演练 | `machine_code`、`time_anchor_demo`、带 anchor 的 `sdk_demo`；298 字节 License、406 字节密封状态，Created → Advanced | 一致 |
| 自动化质量门 | 5 个内部测试 + 6 个 P2 + 15 个 P1 + 4 个机器 + 9 个时间锚，共 39 个通过；严格 Clippy/diff check 通过 | 一致 |
| 完全删除状态 | 明确返回 Created 和新 installation_id，离线无法判断重装；转交 P4 激活/冗余记录 | 有记录的物理边界 |

结论：P3 完成。当前实现提供了可解释机器绑定和失败关闭的本地时间锚，但不承诺抵御管理员删除全部状态或完整虚拟机克隆；这两项由 P4 在线激活、时间票据和设备配额增强。
