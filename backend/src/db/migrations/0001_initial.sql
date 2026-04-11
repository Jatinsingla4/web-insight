-- Migration: 0001_initial
-- Description: Create initial schema for DNS Checker

-- ── Users ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  avatar_url TEXT,
  google_id TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_users_google_id ON users(google_id);
CREATE INDEX idx_users_email ON users(email);

-- ── Brands ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS brands (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  name TEXT NOT NULL,
  last_scan_id TEXT,
  last_scanned_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_brands_user_id ON brands(user_id);
CREATE UNIQUE INDEX idx_brands_user_domain ON brands(user_id, domain);

-- ── Scans ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  brand_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed')),
  tech_stack_json TEXT,
  dns_json TEXT,
  ssl_json TEXT,
  raw_response_r2_key TEXT,
  error_message TEXT,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (brand_id) REFERENCES brands(id) ON DELETE CASCADE
);

CREATE INDEX idx_scans_brand_id ON scans(brand_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at);

-- ── Scheduled Rescans ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scheduled_rescans (
  id TEXT PRIMARY KEY,
  brand_id TEXT NOT NULL UNIQUE,
  cron_expression TEXT NOT NULL DEFAULT '0 0 * * *',
  enabled INTEGER NOT NULL DEFAULT 1,
  last_run_at TEXT,
  next_run_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (brand_id) REFERENCES brands(id) ON DELETE CASCADE
);

CREATE INDEX idx_scheduled_rescans_next_run ON scheduled_rescans(next_run_at)
  WHERE enabled = 1;
