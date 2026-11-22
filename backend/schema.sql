-- ShanX13 AiGG Direct Commander: dedicated customer portal database.
-- Create only in a NEW Cloudflare D1 database. Never migrate shared X13 databases.
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS accounts (
 email TEXT PRIMARY KEY COLLATE NOCASE,
 tenant_id TEXT NOT NULL UNIQUE,
 role TEXT NOT NULL DEFAULT 'customer' CHECK (role IN ('customer','admin')),
 active INTEGER NOT NULL DEFAULT 1 CHECK (active IN(0,1)),
 subscription_status TEXT NOT NULL DEFAULT 'pending' CHECK(subscription_status IN ('pending','trial','active','past_due','suspended','canceled'))
);
CREATE TABLE IF NOT EXISTS agents (
 agent_id TEXT PRIMARY KEY,
 tenant_id TEXT NOT NULL,
 device_id TEXT NOT NULL,
 token_hash TEXT NOT NULL UNIQUE,
 active INTEGER NOT NULL DEFAULT 1 CHECK (active IN(0,1)),
 UNIQUE(tenant_id,device_id)
);
CREATE TABLE IF NOT EXISTS usage_events (
 event_id TEXT PRIMARY KEY,
 tenant_id TEXT NOT NULL,
 agent_id TEXT NOT NULL,
 device_id TEXT NOT NULL,
 kind TEXT NOT NULL,
 outcome TEXT NOT NULL,
 units INTEGER NOT NULL CHECK(units>=0 AND units<=1000000),
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS usage_tenant_recent ON usage_events(tenant_id,created_at DESC);
CREATE INDEX IF NOT EXISTS usage_device_recent ON usage_events(device_id,created_at DESC);
