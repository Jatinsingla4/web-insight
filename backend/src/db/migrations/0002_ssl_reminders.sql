-- Migration: 0002_ssl_reminders
-- Description: Create reminders table for SSL certificate expirations
 
CREATE TABLE IF NOT EXISTS ssl_reminders (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  expiry_date TEXT NOT NULL,
  reminded_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
 
CREATE UNIQUE INDEX idx_ssl_reminders_user_domain ON ssl_reminders(user_id, domain);
CREATE INDEX idx_ssl_reminders_user_id ON ssl_reminders(user_id);
