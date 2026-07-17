# License 密钥轮换与泄漏响应 Runbook

## 正常轮换

1. 在生产 KMS/HSM 创建不可导出的新 Ed25519 key，分配更高 generation 和全新 KeyId。
2. 将新公钥以 `ACTIVE` 加入客户端 KeyRing；旧 key 保持 `VERIFY_ONLY`，不得再签发。
3. 发布包含两个公钥的客户端，等待达到已批准的客户端覆盖率和支持窗口。
4. 签发端切换到新 key，验证 receipt 的 KeyId、generation、请求人、审批人和 SHA-256 已进入不可变审计。
5. 等待旧 key 签发的最长 License/离线宽限到期，再把旧 key 标记 `RETIRED`；泄漏时直接 `REVOKED`。
6. 只有当支持策略允许时，提高客户端 `minimum_generation`，防止降级接受旧信任根。

不得复用 KeyId 指向不同公钥。P4.2 数据库和备份会校验 KeyId/公钥绑定并失败关闭。

## 私钥泄漏

1. 立即停止相关签发服务并冻结审批队列，保全 KMS、CI、签发 receipt、管理员和数据库审计。
2. 在 KMS/HSM 禁用泄漏 key，将客户端状态更新为 `REVOKED`，评估离线客户端暴露窗口。
3. 创建新 KeyId/generation；高风险客户使用人工核验、在线 revocation epoch 或重新签发迁移。
4. 搜索源码、构建产物、日志、备份、工单和聊天系统中的副本；生产秘密不得通过普通 Git 历史清理代替撤销。
5. 发布事件时间线、受影响 License 范围、客户通知和根因整改。

## KMS/HSM 不可用

- 验签和现有 License 运行不依赖签发私钥，应继续失败隔离。
- 停止新签发，不把私钥导出到桌面 CLI，不临时降级为仓库测试 key。
- 按业务连续性计划排队请求；恢复后保持原 request_id，防止重复签发。

## 当前仓库的历史 RSA 私钥

`keys/rsa_private.der` 已被 Git 跟踪，永久视为测试/泄漏材料。任何生产系统不得信任对应公钥。历史清理步骤见 `git-history-secret-cleanup.md`；清理前后都必须先完成真实密钥撤销与轮换。
