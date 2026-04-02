# 综合 Token、CAIP-2 多链适配与强制加密身份管理方案 (最终修订版)

## 方案设计核心

该方案通过引入“语义化 Token”和“多链自动寻址”，实现了 Agent 的极致易用性与安全性。

### 1. 身份与解密：Combined Token
Agent 仅需配置一个环境变量：`KITE_AGENT_TOKEN = "kite_tk_<access_key_id>_<secret_key>"`。
- **解析行为**：SDK 自动从 Token 中提取 ID 以检索配置，并使用 Secret 解密私钥。
- **强制加密**：所有私钥以 `CryptoEnvelope` 形式内联存储在 `agents.toml` 中，彻底弃用明文 PEM 文件。

### 2. 多链适配：CAIP-2 标准
遵循 OWS 的最佳实践，`chain_id` 使用 **CAIP-2** (Chain Agnostic Improvement Proposal) 格式。
- **格式示例**：`eip155:8453` (Base), `eip155:1` (Ethereum), `solana:5eykt...` (Solana)。
- **自动寻址**：Agent 只要指定 `chain_id`，SDK 将向网关发起 `ValidateSignIntent` 请求。网关负责解析该 Agent 绑定在该链上的具体 `wallet_id` 和 `policy_id`。

### 3. 可恢复性与安全预警
- **不可找回性**：Token 仅在创建时展示一次，不存储于本地任何文件。
- **安全警告**：创建成功后，CLI 会显著提示用户立即备份，并告知丢失后只能通过 `revoke` 重新生成。

---

## 详细设计

### 1. 存储结构 (`~/.kitepass/agents.toml`)
```toml
[[agents]]
name = "trading-bot"
access_key_id = "aak_123"
public_key_hex = "..."
encrypted_key = { cipher = "...", ciphertext = "...", kdf = "hkdf-sha256", ... }
```

### 2. 签名流程适配
1. **输入**：`KITE_AGENT_TOKEN` + `chain_id` (如 `eip155:8453`) + `payload`。
2. **本地解析**：分解 Token -> 从 `agents.toml` 加载并解密私钥。
3. **网关发现**：调用 `ValidateSignIntent` (附带 `wallet_selector="auto"`)，网关返回与该 `chain_id` 匹配的钱包 ID。
4. **最终提交**：执行 `submit_signature` 完成业务闭环。

---

## 任务分解 (Task Breakdown)

### 第一阶段：核心代码实现 (Crypto & Config)
- [ ] [NEW] `crates/kitepass-crypto/src/encryption.rs`: 核心加解密与 Combined Token 解析。
- [ ] [MODIFY] `crates/kitepass-config/src/agents.rs`: 迁移至全加密、内联数据模型。

### 第二阶段：CLI 命令适配
- [ ] [MODIFY] `crates/kitepass-cli/src/commands/access_key.rs`: 
    - 强制执行加密。
    - 输出 Combined Token。
    - 增加安全警告信息。
- [ ] [MODIFY] `crates/kitepass-cli/src/commands/sign.rs`: 
    - 适配单 Token 解析流程。
    - 强化基于 CAIP-2 `chain_id` 的自动发现逻辑。
- [ ] [MODIFY] `crates/kitepass-cli/src/commands/profile.rs`: 同步更新显示逻辑。

### 第三阶段：文档与体系化建设
- [ ] [MODIFY] `kitepass-cli/docs/cli-manual.md`: 更新第 4 & 5 章，反映单 Token、CAIP-2 标准和多链自动映射用法。
- [ ] [NEW] `kitepass-cli/docs/agent-security-design.md`: 详解系统安全模型、存储格式和加密细节。

## 验证计划

1. **跨链自动发现验证**：
   - 使用同一 Combined Token，分别带上 `eip155:1` 和 `eip155:8453` 执行签名，验证是否能分别路由到对应的钱包。
2. **零文件依赖验证**：确认删除所有 `.pem` 后，系统依然能正常工作。
3. **文档一致性**：确认 `cli-manual.md` 中的示例代码符合 CAIP-2 标准。
