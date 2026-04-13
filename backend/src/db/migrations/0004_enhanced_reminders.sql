-- Migration: 0004_enhanced_reminders
-- Description: Add support for multi-recipient notifications and configurable thresholds

ALTER TABLE ssl_reminders ADD COLUMN notify_emails TEXT DEFAULT '[]';
ALTER TABLE ssl_reminders ADD COLUMN threshold_days TEXT DEFAULT '[30, 7, 1]';
ALTER TABLE ssl_reminders ADD COLUMN is_enabled INTEGER NOT NULL DEFAULT 1;
