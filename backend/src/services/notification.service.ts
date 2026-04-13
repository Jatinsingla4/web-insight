export interface EmailPayload {
  to: string | string[];
  subject: string;
  html: string;
}

export class NotificationService {
  private readonly apiKey: string;
  private readonly from: string = "Web Insight <alerts@web-insight.app>";

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  async sendEmail(payload: EmailPayload) {
    if (!this.apiKey || this.apiKey === "placeholder") {
      console.warn("[NotificationService] Missing API Key, logging email to console:");
      console.log(`[EMAIL] To: ${payload.to} | Subject: ${payload.subject}`);
      return { success: true, mocked: true };
    }

    try {
      const response = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: this.from,
          to: payload.to,
          subject: payload.subject,
          html: payload.html,
        }),
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Resend API Error: ${error}`);
      }

      return await response.json();
    } catch (error) {
      console.error("[NotificationService] Failed to send email:", error);
      throw error;
    }
  }

  generateSslExpiryTemplate(data: {
    domain: string;
    daysLeft: number;
    expiryDate: string;
    userName: string;
  }) {
    const isCritical = data.daysLeft <= 3;
    const color = isCritical ? "#ef4444" : "#f59e0b";
    
    return `
      <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #1f2937;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #4f46e5; margin: 0;">Web Insight</h1>
          <p style="color: #6b7280; font-size: 14px; margin-top: 5px;">Intelligence Mastery & Security Audit</p>
        </div>
        
        <div style="background-color: #f9fafb; border-radius: 12px; padding: 30px; border: 1px solid #e5e7eb;">
          <h2 style="margin-top: 0; color: ${color};">SSL Expiry Alert</h2>
          <p>Hi ${data.userName},</p>
          <p>This is an automated security alert regarding your domain: <strong>${data.domain}</strong>.</p>
          
          <div style="background-color: #ffffff; padding: 20px; border-radius: 8px; margin: 20px 0; border: 2px solid ${color};">
            <p style="margin: 0; font-size: 14px; text-transform: uppercase; font-weight: bold; color: #6b7280;">Status</p>
            <p style="margin: 5px 0 0 0; font-size: 24px; font-weight: 900; color: ${color};">Expiring in ${data.daysLeft} Day${data.daysLeft === 1 ? '' : 's'}</p>
            <p style="margin: 10px 0 0 0; font-size: 14px; color: #374151;">Expiry Date: <strong>${new Date(data.expiryDate).toLocaleDateString()}</strong></p>
          </div>
          
          <p>An expired SSL certificate will cause browsers to block your website and stop all traffic. Please renew your certificate immediately to avoid downtime.</p>
          
          <a href="https://web-insight.app/dashboard" style="display: inline-block; background-color: #4f46e5; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: bold; margin-top: 20px;">View Security Dashboard</a>
        </div>
        
        <div style="text-align: center; margin-top: 30px; font-size: 12px; color: #9ca3af;">
          <p>&copy; ${new Date().getFullYear()} Web Insight. All rights reserved.</p>
          <p>You received this because monitoring is enabled for ${data.domain}.</p>
        </div>
      </div>
    `;
  }
}
