# P2：产品业务集成

## 目标

把 P1 的只读 `AuthorizationContext` 深度接入真实产品关键路径，使授权不是单一启动布尔检查。

## 实现前确认（进入本步骤时填写）

- [x] P1 所有验收通过：16 个测试、严格 Clippy、CLI 闭环均通过。
- [x] 用户授权创建虚拟 SDK/Demo；本步骤在当前 crate 新增 `demo_sdk` 模块和 `sdk_demo` 二进制入口，不假设外部产品仓库。
- [x] 高价值功能：GPU、DeepZoom、批处理算法；额度：并行任务数、连接设备数；资源：模型 ID、设备 ID。
- [x] 失败策略：SDK 返回稳定业务错误，不把原始 License 文件或可写授权布尔值暴露给模块；CLI 只显示可解释结果。

状态：实现前确认、编码和实现后验收均已完成。

## 详细实现事项

1. [x] 定义产品侧 `DemoImageSdk`，构造函数只接收 P1 生成的 `AuthorizationContext`，并以 `Arc` 向内部组件注入。
2. [x] 算法注册：CPU 基础算法始终存在；GPU、DeepZoom、批处理只在相应 Feature 为 true 时注册。
3. [x] 高价值调用：运行算法时再次检查 Feature，形成“注册处 + 调用处”两点业务绑定。
4. [x] 任务调度：`max_parallel_jobs` 直接限制并行任务许可；使用 RAII permit，任务结束或异常释放名额。
5. [x] 模型加载：`resource_scope.model_ids` 是允许列表，空列表按失败关闭解释为无模型授权。
6. [x] 设备访问：`resource_scope.device_ids` 限制设备标识，`max_devices` 限制同时连接数量；重复连接幂等。
7. [x] 错误模型：区分功能未授权、算法未注册、资源拒绝、并行额度耗尽、设备额度耗尽和内部状态异常。
8. [x] `sdk_demo`：读取 License/公钥并验证，创建 SDK，展示注册算法、模型运行和设备连接结果。
9. [x] 集成测试：功能组合、双点校验、并发边界与释放、8 线程额度竞争、模型范围、设备范围/数量、重复连接。
10. [x] README 增加 Demo 命令；完成测试、严格 Clippy、CLI 端到端演练和 diff 检查。

## 预期文件（进入本步骤时按真实产品修订）

- `src/demo_sdk/{mod,error,algorithm,scheduler,model,device}.rs`：虚拟 SDK 产品适配层。
- `src/bin/sdk_demo.rs`：License 验证和 SDK 启动装配。
- `tests/demo_sdk.rs`：P2 集成测试。
- `licenses/payload.example.json`：补充设备范围，作为 Demo 输入。

## 验收标准

- 不存在可写的全局 `Licensed=true`。
- Patch 单一启动检查不能自动解锁所有核心能力。
- 所有 Feature、Limit、ResourceScope 都至少有一个真实业务消费者。
- 未授权路径失败关闭，续费/升级入口仍可用。
- 测试、clippy 和产品回归测试通过。

## 问题与新思路

### 没有真实产品仓库

- 现象：当前仓库只有 LicenseSystem，没有图像 SDK 或桌面软件业务代码。
- 影响：无法证明对真实业务路径完成集成。
- 用户决定：允许虚拟一个 SDK 或创建 Demo。
- 新思路：创建小而完整的虚拟图像 SDK，把文档第 10.2 节的算法注册、任务调度、模型加载和设备访问全部变成可执行代码；模块边界保持可替换，未来真实产品可复用授权适配模式。
- 验证办法：CLI 演练和集成测试必须证明授权数据实际改变组件行为，而非只打印 License 状态。

## 实现后同步

| 设计授权字段 | 实际消费者 | 测试/演练 | 同步状态 |
| --- | --- | --- | --- |
| `features.gpu/deepzoom/batch` | `AlgorithmRegistry` 注册和 `run` 调用入口 | 未授权 DeepZoom 不注册；GPU、Batch 按组合注册 | 一致 |
| `limits.max_parallel_jobs` | `JobScheduler` 的原子计数与 RAII `JobPermit` | 额度边界、释放恢复、8 线程竞争仅 2 个成功 | 一致 |
| `resource_scope.model_ids` | `ModelStore::require_model` | M008 通过，M999 返回资源拒绝 | 一致 |
| `resource_scope.device_ids` | `DeviceManager::connect` | 非白名单 CAM-999 拒绝 | 一致 |
| `limits.max_devices` | `DeviceManager` 连接集合 | 两个连接后拒绝第三个；断开后可连接；重复连接幂等 | 一致 |
| 不可变授权上下文 | `DemoImageSdk` 构造后以 `Arc` 注入组件 | SDK 不读取 License 文件、不暴露可写授权布尔值 | 一致 |
| Demo 启动装配 | `src/bin/sdk_demo.rs` | 生成密钥、签发 299 字节 License、GPU/M001 处理和 CAM-001 连接成功 | 一致 |
| 自动化质量门 | 全部 target | 1 个内部测试 + 15 个 P1 测试 + 6 个 P2 测试；严格 Clippy 和 diff check 通过 | 一致 |

结论：P2 虚拟图像 SDK 已完成。它证明 Feature、Limit 和 ResourceScope 会直接改变业务组件行为，不依赖单一 `isLicensed` 检查。真实产品接入时可替换组件实现并保留相同授权注入模式。
