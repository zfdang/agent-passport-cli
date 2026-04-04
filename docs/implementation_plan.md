# Agent Passport Token And Encrypted Profile Migration Notes

> **状态**：历史实现说明 / 已基本落地
>
> 这份文档原本是 Agent Passport Token、加密本地身份存储、以及 CAIP-2
> 路由的实现计划。截止 2026-04-03，其中大部分已经在当前
> `kitepass-cli` 代码中落地。

## 当前已落地的行为

### 1. Agent Passport Token

当前格式是：

```text
kite_apt_<agent_passport_id>__<secret_key>
```

当前实现特点：

- `kitepass passport create` 只展示一次 Agent Passport Token
- CLI 不会把 Agent Passport Token 直接写入本地文件
- 运行时通过 `KITE_AGENT_PASSPORT_TOKEN` 读取它
- Token 中的 `agent_passport_id` 用于匹配本地 profile
- Token 中的 `secret_key` 用于解密本地加密私钥

### 2. 本地加密存储

当前本地目录是：

- `~/.kitepass/config.toml`
- `~/.kitepass/access-token.secret`
- `~/.kitepass/agents.toml`

其中：

- principal session token 以加密 envelope 形式存入 `config.toml`
- 本地 agent 私钥以内联 `CryptoEnvelope` 形式存入 `agents.toml`
- 明文 PEM 文件不再是正常运行路径的一部分

### 3. CAIP-2 链路由

当前签名接口继续使用 CAIP-2 `chain_id`，例如：

- `eip155:1`
- `eip155:8453`

当前行为：

- `kitepass sign --validate` 支持 `wallet_id` 显式指定
- 如果未显式给出 `wallet_id`，CLI 会发送 `wallet_selector=auto`
- Gateway 根据当前 agent passport、policy、wallet binding 和 `chain_id`
  做路由解析

### 4. 当前签名调用链

当前 `kitepass sign` 的实现顺序是：

1. `validate_sign_intent`
2. `create_session_challenge`
3. `create_session`
4. 最终提交 sign request

`kitepass sign` 和 `kitepass sign --broadcast` 必须提供 `KITE_AGENT_PASSPORT_TOKEN`。

## 仍应记住的边界

- 当前 `wallet import` 只支持 EVM family
- `kitepass sign --validate` 比 `kitepass sign` 更宽松
  - 它既可以走 principal session，也可以走 `KITE_AGENT_PASSPORT_TOKEN`
- `kitepass sign` 是真正的 runtime signing path
  - 它要求本地 agent key 可解密、可签名

## 这份文档现在的作用

它更适合作为“这次迁移已经落地了什么”的背景记录，而不是新的实现计划。

如果需要查看当前对外可用的真实使用方式，优先看：

- `README.md`
- `docs/cli-manual.md`
- `docs/principal-auth-and-agent-passport-flow.md`
- `docs/agent-security-design.md`
