import { generateId } from "../lib/crypto";
import type { SslReminderInput } from "@dns-checker/shared";

export class ReminderService {
  constructor(private readonly db: D1Database) {}

  async setSslReminder(userId: string, input: SslReminderInput) {
    const notifyEmailsJson = JSON.stringify(input.notifyEmails);
    const thresholdDaysJson = JSON.stringify(input.thresholdDays);
    const isEnabled = input.isEnabled ? 1 : 0;

    await this.db.prepare(
      `INSERT INTO ssl_reminders (
        id, user_id, domain, expiry_date, notify_emails, threshold_days, is_enabled, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(user_id, domain) DO UPDATE SET
        expiry_date = excluded.expiry_date,
        notify_emails = excluded.notify_emails,
        threshold_days = excluded.threshold_days,
        is_enabled = excluded.is_enabled,
        reminded_at = NULL,
        created_at = datetime('now')`,
    )
      .bind(
        generateId(), 
        userId, 
        input.domain, 
        input.expiryDate, 
        notifyEmailsJson, 
        thresholdDaysJson, 
        isEnabled
      )
      .run();

    return { success: true };
  }

  async listReminders(userId: string) {
    const { results } = await this.db.prepare(
      `SELECT * FROM ssl_reminders WHERE user_id = ? ORDER BY created_at DESC`,
    )
      .bind(userId)
      .all();

    return results.map(r => ({
      ...r,
      notifyEmails: JSON.parse(r.notify_emails as string || "[]"),
      thresholdDays: JSON.parse(r.threshold_days as string || "[30, 7, 1]"),
      isEnabled: Boolean(r.is_enabled),
    }));
  }

  async deleteReminder(userId: string, id: string) {
    await this.db.prepare(
      `DELETE FROM ssl_reminders WHERE id = ? AND user_id = ?`,
    )
      .bind(id, userId)
      .run();

    return { success: true };
  }

  /**
   * Finds certificates that are hitting a notification threshold today.
   */
  async getExpiringCertificates() {
    // Find all enabled reminders
    const { results } = await this.db.prepare(
      `SELECT r.*, u.email as user_email, u.name as user_name
       FROM ssl_reminders r
       JOIN users u ON r.user_id = u.id
       WHERE r.is_enabled = 1`
    ).all();

    const expiring: any[] = [];
    const now = new Date();

    for (const row of results) {
      const expiry = new Date(row.expiry_date as string);
      const diffDays = Math.ceil((expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
      
      const thresholds = JSON.parse(row.threshold_days as string || "[30, 7, 1]") as number[];
      const emails = JSON.parse(row.notify_emails as string || "[]") as string[];
      
      // Add the user's primary email if no custom emails are set
      const recipientEmails = emails.length > 0 ? emails : [row.user_email as string];

      if (thresholds.includes(diffDays)) {
        expiring.push({
          id: row.id,
          domain: row.domain,
          expiryDate: row.expiry_date,
          daysLeft: diffDays,
          recipients: recipientEmails,
          userName: row.user_name,
        });
      }
    }

    return expiring;
  }

  async markAsReminded(id: string) {
    await this.db.prepare(
      `UPDATE ssl_reminders SET reminded_at = datetime('now') WHERE id = ?`
    )
      .bind(id)
      .run();
  }
}
