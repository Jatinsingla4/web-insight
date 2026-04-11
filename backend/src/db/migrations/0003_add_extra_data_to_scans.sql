-- Migration: 0003_add_extra_data_to_scans
-- Description: Add extra_data_json column to store extended scan results

ALTER TABLE scans ADD COLUMN extra_data_json TEXT;
