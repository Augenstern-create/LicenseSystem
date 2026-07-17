# 发布包允许列表

实际产品流水线必须从空目录按允许列表复制，不得直接压缩整个仓库。

允许按产品角色选择：

- 客户端：`license_system` 库制品、产品主程序、必要运行库、对应产品公钥、用户文档。
- 在线服务：`online_secure_server`、`online_backup_verify`、受控配置 schema、迁移/运维文档。
- 隔离签发环境：`license_issue_governed`、受控请求 schema；仅在签发环境从 KMS/HSM 获取签名能力。

禁止进入任何客户或服务发布包：

- `keys/` 下所有私钥和仓库历史测试密钥；
- `tests/`、`fuzz/`、固定私钥 seed、测试数据库、备份和 corpus；
- `online_demo`、`online_server`、`online_sqlite_server` 及其固定开发密钥；
- `target/`、`.git/`、CI 临时文件、崩溃 dump 和本地日志；
- 管理 token、TLS 私钥、在线签名私钥和 KMS 导出材料；
- 客户 payload、已签发 License、机器原始标识和未脱敏审计导出。

流水线应生成最终文件清单、每文件 SHA-256、SBOM、代码签名结果和构建 commit，并由第二人复核。
