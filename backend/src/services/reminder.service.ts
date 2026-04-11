import { generateId } from "../lib/crypto";
import type { SslReminderInput } from "@dns-checker/shared";
 
export class ReminderService {
  constructor(private readonly db: D1Database) {}
 
  async setSslReminder(userId: string, input: SslReminderInput) {
    // If a reminder already exists for this user and domain, update it
    await this.db.prepare(
      `INSERT INTO ssl_reminders (id, user_id, domain, expiry_date, created_at)
       VALUES (?, ?, ?, ?, datetime('now'))
       ON CONFLICT(user_id, domain) DO UPDATE SET
         expiry_date = excluded.expiry_date,
         reminded_at = NULL,
         created_at = datetime('now')`,
    )
      .bind(generateId(), userId, input.domain, input.expiryDate)
      .run();
 
    return { success: true };
  }
 
  async listReminders(userId: string) {
    const { results } = await this.db.prepare(
      `SELECT * FROM ssl_reminders WHERE user_id = ? ORDER BY created_at DESC`,
    )
      .bind(userId)
      .all();
 
    return results;
  }
 
  async deleteReminder(userId: string, id: string) {
    await this.db.prepare(
      `DELETE FROM ssl_reminders WHERE id = ? AND user_id = ?`,
    )
      .bind(id, userId)
      .run();
 
    return { success: true };
  }
}
