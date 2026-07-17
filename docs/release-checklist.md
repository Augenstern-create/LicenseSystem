# LicenseSystem 发布安全检查表

发布负责人和安全复核人必须逐项签字；任何“阻塞”项不得以文档完成代替实际证据。

## 自动检查

- [ ] `cargo test --all-targets`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] Python `scripts/verify_license_vector.py`
- [ ] `scripts/release_secret_audit.ps1` 无阻塞发现
- [ ] `git diff --check`
- [ ] cargo-fuzz 在批准的 nightly/CI 预算内无 crash，corpus 已归档

## 密钥与审批

- [ ] 生产私钥在 KMS/HSM 中不可导出，开发/测试/生产信任根不同
- [ ] KeyId、generation、ACTIVE/VERIFY_ONLY/RETIRED/REVOKED 状态已复核
- [ ] 高风险签发双人审批和不可变 receipt 审计可查询
- [ ] `keys/rsa_private.der` 对应材料已撤销，并经审批完成 Git 历史处理

## 制品与渠道

- [ ] 只打包产品需要的库/二进制、公钥、配置 schema 和用户文档
- [ ] 排除 `keys/` 私钥、`target/`、测试向量私钥 seed、Demo 固定密钥、数据库和备份
- [ ] Release profile 构建，可复现版本号/SBOM 已记录
- [ ] 使用组织代码签名证书签名，发布渠道验证签名和 SHA-256
- [ ] 崩溃日志与遥测按支持 Runbook 脱敏

## 在线运维

- [ ] 有效 TLS、loopback 管理面、企业身份、WAF/按来源限流
- [ ] 指标、日志、证书、磁盘和备份告警已接入值班平台
- [ ] 备份不可变异地保存，恢复演练满足经批准 RPO/RTO
- [ ] 私钥泄漏、误撤销、KMS 不可用、时钟异常演练有日期、责任人和改进项

## 发布结论

- 发布版本/commit：待填写
- 发布负责人：待填写
- 安全复核人：待填写
- 日期：待填写
- 结论：当前阻塞（生产 KMS/HSM、责任人、代码签名、历史私钥处理和真实灾备证据未提供）
