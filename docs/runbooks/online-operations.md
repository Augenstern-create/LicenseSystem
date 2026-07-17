# 在线 License 服务部署、监控与恢复 Runbook

## 适用范围

本文适用于 `online_secure_server` 的单节点 SQLite 参考部署。它提供 TLS、独立 loopback 管理面、Bearer 管理凭据、限流、指标和 SQLite 在线备份，但不替代组织的 KMS/HSM、OIDC/mTLS、WAF、集中监控、备份平台和跨区域容灾。

## 启动前检查

1. 使用受控流程生成独立在线服务 Ed25519 密钥。生产环境不得使用仓库或 Demo 的固定密钥。
2. 私钥文件只允许服务账号读取；客户端和 Web 根目录只能分发公钥。
3. 准备包含正确 SAN 的有效 TLS 证书和私钥。自签证书只允许测试。
4. 创建 SQLite 与备份目录，限制为服务账号读写；备份卷应启用加密和异地复制。
5. 设置至少 32 字节高熵 `LICENSE_ADMIN_TOKEN`，通过秘密管理器注入；设置不含个人敏感信息的 `LICENSE_ADMIN_CREDENTIAL_ID`。
6. 管理监听地址必须是 loopback。远程管理通过受控堡垒机、VPN 或 mTLS 反向代理进入，不直接暴露端口。

启动命令：

```powershell
$env:LICENSE_ADMIN_TOKEN = '<secret-manager-injected-token>'
$env:LICENSE_ADMIN_CREDENTIAL_ID = 'ops-admin-production'
cargo run --release --bin online_secure_server -- `
  data/license.sqlite online-prod-2026 keys/online-private.key `
  tls/fullchain.pem tls/private-key.pem backups `
  0.0.0.0:3443 127.0.0.1:3444
```

启动失败时不得自动换新签名密钥。若数据库报告签名身份不一致，应停止并核对 KeyId、密钥版本和恢复来源。

## 网络与 TLS

- 公共端口只承载 `/v1/activate`、`/v1/lease`、`/v1/time-ticket`。
- 管理端口只绑定 loopback，承载 `/admin/v1/*`；所有端点要求 Bearer 凭据。
- 上游负载均衡必须使用 HTTPS 回源或运行在同一受控主机；禁止在不可信网络中明文转发管理 token。
- 证书轮换采用并行文件写入和受控重启。重启前验证证书链、SAN、有效期和私钥匹配。
- 建议在边缘配置每来源限流、连接数限制、请求体限制、超时和 DDoS 防护；进程内限流是全局最后防线，不区分来源。

## 指标与告警

认证后读取 `GET https://127.0.0.1:3444/admin/v1/metrics`。指标不包含请求体、token、完整 LicenseId 或 installation 值。

建议阈值：

- `responses_5xx`：5 分钟内大于 0 告警；持续增加立即检查 SQLite I/O、磁盘、锁和证书。
- `rate_limited`：5 分钟内超过正常基线或连续增长告警；结合边缘来源数据判断误配置或攻击。
- `requests_in_flight`：持续不归零或接近部署连接上限告警。
- 4xx 比例：15 分钟超过 20% 告警，区分客户配置错误、过期/撤销和扫描流量。
- 磁盘可用空间：低于 20% 告警、低于 10% 严重；同时监控数据库、WAL 和备份卷。
- TLS 证书：到期前 30 天告警、7 天严重。
- 备份：超过计划周期 2 倍没有成功备份或验证失败时严重告警。

当前指标是进程生命周期累计值，重启会归零。生产应由 Prometheus/OpenTelemetry 等外部系统定期采集并持久化。

## 备份

使用认证管理端点 `POST /admin/v1/backup`。服务端在配置目录生成文件名；请求不能指定路径。不要直接复制运行中的 `.sqlite`、`-wal`、`-shm` 组合代替在线备份。

建议策略：

- 每小时在线备份，保留 48 小时；每日备份保留 35 天；月度备份按合同和合规要求保留。
- 备份生成后立即执行完整性与签名身份验证，然后由外部备份平台加密、不可变存储并异地复制。
- 管理 token、TLS 私钥和在线签名私钥不得与数据库备份存放在同一归档中。

验证命令只需要在线公钥：

```powershell
cargo run --bin online_backup_verify -- `
  backups/license-backup-<timestamp>-<uuid>.sqlite `
  online-prod-2026 keys/online-public.key
```

## 恢复演练

1. 停止服务并记录事故时间，保留当前数据库、WAL 和日志副本，不覆盖证据。
2. 选择恢复点，运行 `online_backup_verify`；验证失败立即换用更早备份并升级事件。
3. 把已验证备份复制到新的数据库路径，不覆盖原数据库。
4. 使用原 KeyId 和对应在线私钥启动服务；签名身份不匹配必须失败关闭。
5. 从管理端读取审计；用已保存 request_id 重试激活/租约，确认幂等响应与恢复点一致。
6. 检查恢复点之后可能丢失的激活、撤销和租约操作。撤销丢失属于高风险，必要时提高 revocation epoch 或临时停服。
7. 切换流量，持续观察 5xx、4xx、限流和磁盘；记录 RPO/RTO 与改进项。

单节点参考目标：备份周期决定 RPO，手工恢复目标 RTO 为 60 分钟。没有外部备份调度和实际演练证据前，不得把该目标写入客户 SLA。

## 事件处置

### 管理 token 泄漏

立即撤销入口、从秘密管理器生成新 token、重启管理服务并检查审计。当前参考实现是单凭据，无法无重启平滑轮换；生产应迁移到短期 OIDC/mTLS 凭据。

### 在线签名私钥泄漏

隔离服务、停止签发、保全日志和数据库，启用新的 KeyId/密钥并更新客户端信任根。旧 KeyId 的处理必须结合已签票据最长有效期；不得只替换文件后继续使用同一 KeyId，因为数据库会拒绝身份不一致。

### SQLite 损坏或磁盘故障

停止写入，保留原文件，按恢复流程使用最近已验证备份。不要在唯一副本上运行修复命令。

### 误撤销

当前撤销是单向状态，参考 API 不提供“取消撤销”。由双人审批确认后签发/注册新的 entitlement 或执行经审计的数据修复方案；禁止直接临时降低 epoch。

### 时间异常

核对主机 UTC/NTP。服务器时间票据和 lease 使用服务 UTC；大幅时间跳变时暂停签发并检查 P3 客户端时间锚告警。

## 尚未完成的生产依赖

- KMS/HSM 不可导出私钥及审批工作流。
- 多凭据、短期身份、mTLS/OIDC 和权限分级。
- 外部 WAF/按来源限流、集中日志与指标平台。
- 自动备份调度、不可变异地存储、恢复编排和定期演练。
- 多节点数据库、自动故障转移和跨区域灾备。
- 正式责任人、值班表、客户 SLA、RPO/RTO 审批记录。
