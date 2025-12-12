# Unified LLM Gateway v2.3.0 部署指南

## D) Cloudflare 控制台图形化部署步骤

### 1. 创建 Worker
1. 登录 Cloudflare Dashboard。
2. 进入 **Workers & Pages** -> **Create Application** -> **Create Worker**。
3. 命名为 `llm-gateway`，点击 **Deploy**。
4. 点击 **Edit Code**，将 `index.tsx` (或者 `worker.js`) 的内容完全粘贴进去，保存并部署。

### 2. 创建并绑定数据库 (D1)
1. 在 **Workers & Pages** -> **D1** -> **Create Database**。
2. 命名为 `llm_db`，点击 Create。
3. 回到刚才创建的 Worker (`llm-gateway`) -> **Settings** -> **Bindings**。
4. 点击 **Add** -> **D1 Database**。
   - **Variable name**: `DB` (必须完全大写，不能改)。
   - **Database**: 选择 `llm_db`。
5. 点击 **Deploy** (绑定变更需要重新部署才能生效)。

### 3. 设置加密密钥 (Secrets)
1. 在 Worker -> **Settings** -> **Variables and Secrets**。
2. 点击 **Add**，添加以下变量：
   - `ADMIN_PASSWORD`: 设置你的后台管理密码 (例如 `MySecurePass123`)。
   - `MASTER_KEY`: 生成一个 32 位以上的随机字符串 (例如 `8f9e3b2a1c4d5e6f7a8b9c0d1e2f3a4b`)，用于加密 API Key。
   - `SESSION_SECRET`: (可选) 用于 Cookie 签名，不填默认使用 MASTER_KEY。

### 4. 初始化数据库表
1. 进入 D1 Database (`llm_db`) -> **Console** 标签页。
2. 复制 `schema_safe.sql` 的内容粘贴并点击 **Execute**。
3. (仅当需要重置时) 才使用 `schema_reset.sql`，这会删除所有数据。

---

## E) 后台最小配置示例

访问 `https://你的-worker-域名/admin` 并登录。

### 1. 添加 Provider (上游服务商)

| 类型 | Name (随意) | Type | Base URL (例子) | Path (可选) | API Key |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **OpenAI** | Official | `openai` | `https://api.openai.com` | (留空) | `sk-...` |
| **中转/OneAPI** | Cheap Relay | `openai_compat_loose` | `https://api.deepseek.com` | (留空) | `sk-...` |
| **Claude** | Anthropic | `anthropic` | `https://api.anthropic.com` | (留空) | `sk-ant-...` |
| **Gemini** | Google | `gemini` | `https://generativelanguage.googleapis.com` | (留空) | `AIza...` |

> **注意**: Base URL 不要带 `/v1` 后缀，网关会自动拼接。如果你的中转商非要带 `/v1` 才能访问，可以在 Base URL 填 `https://api.xx.com`，然后在 Path 填 `/v1`。

### 2. 配置 Routes (路由规则)

| Prefix (前缀) | 指向 Provider | 作用 |
| :--- | :--- | :--- |
| `gpt-` | Official | 所有 `gpt-` 开头的模型 (如 `gpt-4o`) 走 OpenAI |
| `claude-` | Anthropic | 所有 `claude-` 开头的模型走 Claude |
| `gemini-` | Google | 所有 `gemini-` 开头的模型走 Google |

### 3. 生成 Client Key
1. 在 "Client Keys" 区域输入设备名 (如 "iPhone Chatbox")。
2. 点击 "Generate Key"。
3. **立即复制** 显示的 `sk-gw-xxxx`，这是你唯一的查看机会。

### 4. 客户端填写 (Chatbox / 沉浸式翻译等)

- **API Host**: `https://你的-worker-域名`
- **API Key**: `sk-gw-xxxx` (刚才生成的)
- **Model**:
  - **自动路由**: 直接填 `gpt-4o` (会匹配 `gpt-` 规则)。
  - **强制指定**: 填 `openai:gpt-4o` (强制走 OpenAI Provider，忽略路由表)。
