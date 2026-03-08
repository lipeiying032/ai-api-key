-- Unified LLM Gateway v3.1.0 - Safe Schema (Idempotent)
-- 可多次执行，不会破坏已有数据
 
CREATE TABLE IF NOT EXISTS providers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    type        TEXT NOT NULL,         -- openai | openai_compat_loose | anthropic | gemini
    base_url    TEXT NOT NULL,
    path        TEXT DEFAULT '',
    api_key_enc TEXT NOT NULL,         -- AES-GCM 加密后的 API Key (base64)
    iv          TEXT NOT NULL,         -- AES-GCM IV (base64)
    salt        TEXT DEFAULT NULL,     -- [v3.1.0新增] PBKDF2 随机 salt (base64), NULL 表示旧格式
    is_enabled  INTEGER DEFAULT 1,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS routes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix      TEXT NOT NULL UNIQUE,  -- 模型前缀, 如 "gpt-", "claude-"
    provider_id INTEGER NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clients (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    key_hash    TEXT NOT NULL UNIQUE,  -- SHA-256(raw_key)
    key_prefix  TEXT NOT NULL,         -- 用于展示, 如 "sk-gw-xxxx"
    is_active   INTEGER DEFAULT 1,
    last_used_at DATETIME DEFAULT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS access_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    client_name   TEXT,
    provider_name TEXT,
    model         TEXT,
    is_stream     INTEGER DEFAULT 0,
    status        INTEGER,
    duration_ms   INTEGER,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 索引优化
CREATE INDEX IF NOT EXISTS idx_routes_prefix       ON routes(prefix);
CREATE INDEX IF NOT EXISTS idx_clients_key_hash    ON clients(key_hash);
CREATE INDEX IF NOT EXISTS idx_access_logs_created ON access_logs(created_at);

-- ============================================================
-- 迁移脚本：从 v3.0.x 升级到 v3.1.0
-- 如果 providers 表已存在但缺少 salt 列，执行以下语句：
-- (D1 Console 中手动执行)
-- ============================================================
-- ALTER TABLE providers ADD COLUMN salt TEXT DEFAULT NULL;