# 客户 License 支持流程

## 机器迁移与解绑

1. 核验客户、合同、LicenseId 后缀和 installation_id，不收集原始硬件序列号。
2. 在线客户通过认证管理面执行解绑，reason 关联工单号；审计 actor 来自服务凭据。
3. 离线 node-locked 客户由受治理签发流程生成替换 License；旧设备仍可运行的风险按合同和 revocation 能力处理。
4. 不直接降低机器阈值或修改客户本地时间锚文件。

## 离线续期

1. 使用结构化 payload，保留原客户/产品范围，仅更新经批准期限、功能和 generation。
2. 永久、超期限或超额度请求必须有两个独立审批人。
3. 向客户传递 `.lic` 和公钥版本说明，不传递私钥、签发 token 或内部审计详情。
4. 客户验证失败时收集稳定错误码、应用版本、KeyId 和 LicenseId 后缀，避免收集完整机器标识。

## 误撤销与恢复

撤销代际不回绕。误撤销需双人确认后注册/签发新的 entitlement 或 License，不直接在数据库降低 epoch。记录客户影响、临时措施和根因。

## 日志脱敏

允许：错误码、KeyId、应用版本、LicenseId 最后 8 个十六进制字符、时间和请求关联 ID。

禁止：完整 License 文件、签名私钥、管理员 token、完整 customer_id、原始机器标识、完整 installation_id 和未脱敏请求体。
