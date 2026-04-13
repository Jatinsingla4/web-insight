import * as jose from "jose";
import type { Session, User } from "@dns-checker/shared";
import { SESSION_DURATION_MS } from "@dns-checker/shared";
import { generateId, generateSessionToken, sha256 } from "../lib/crypto";
import type { Env } from "../lib/env";

interface GoogleTokenResponse {
  access_token: string;
  id_token: string;
  token_type: string;
}

interface GoogleUserInfo {
  sub: string;
  email: string;
  name: string;
  picture: string;
}

export class AuthService {
  constructor(private readonly env: Env) {}

  /** Build the Google OAuth authorization URL. */
  getAuthUrl(redirectUri: string, state: string): string {
    const params = new URLSearchParams({
      client_id: this.env.GOOGLE_CLIENT_ID,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "openid email profile",
      state,
      access_type: "offline",
      prompt: "consent",
    });

    return `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
  }

  /** Exchange authorization code for tokens and user info. */
  async handleCallback(
    code: string,
    redirectUri: string,
  ): Promise<{ sessionToken: string; user: User }> {
    // Exchange code for tokens
    const tokenResponse = await fetch(
      "https://oauth2.googleapis.com/token",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: this.env.GOOGLE_CLIENT_ID,
          client_secret: this.env.GOOGLE_CLIENT_SECRET,
          redirect_uri: redirectUri,
          grant_type: "authorization_code",
        }),
        signal: AbortSignal.timeout(8000),
      },
    );

    if (!tokenResponse.ok) {
      const text = await tokenResponse.text();
      throw new Error(`Token exchange failed: ${text}`);
    }

    const tokens = (await tokenResponse.json()) as GoogleTokenResponse;

    // Verify the ID token signature against Google's JWKS (do NOT just decode)
    const JWKS = jose.createRemoteJWKSet(new URL("https://www.googleapis.com/oauth2/v3/certs"));
    const { payload } = await jose.jwtVerify(tokens.id_token, JWKS, {
      issuer: ["https://accounts.google.com", "accounts.google.com"],
      audience: this.env.GOOGLE_CLIENT_ID,
    });
    const claims = payload as unknown as GoogleUserInfo;

    // Upsert user in D1
    const user = await this.upsertUser({
      googleId: claims.sub,
      email: claims.email,
      name: claims.name,
      avatarUrl: claims.picture,
    });

    // Create session — store hash of token as KV key so raw tokens are never at rest
    const sessionToken = generateSessionToken();
    const tokenHash = await sha256(sessionToken);
    const session: Session = {
      userId: user.id,
      email: user.email,
      name: user.name,
      avatarUrl: user.avatarUrl,
      expiresAt: Date.now() + SESSION_DURATION_MS,
    };

    await this.env.SESSIONS.put(
      `session:${tokenHash}`,
      JSON.stringify(session),
      { expirationTtl: SESSION_DURATION_MS / 1000 },
    );

    return { sessionToken, user };
  }

  /** Validate a session token and return the session. */
  async validateSession(token: string): Promise<Session | null> {
    const tokenHash = await sha256(token);
    const data = await this.env.SESSIONS.get<Session>(
      `session:${tokenHash}`,
      "json",
    );
    if (!data) return null;
    if (data.expiresAt < Date.now()) {
      await this.env.SESSIONS.delete(`session:${tokenHash}`);
      return null;
    }
    return data;
  }

  /** Destroy a session. */
  async destroySession(token: string): Promise<void> {
    const tokenHash = await sha256(token);
    await this.env.SESSIONS.delete(`session:${tokenHash}`);
  }

  private async upsertUser(info: {
    googleId: string;
    email: string;
    name: string;
    avatarUrl: string;
  }): Promise<User> {
    // Check for existing user
    const existing = await this.env.DB.prepare(
      `SELECT * FROM users WHERE google_id = ?`,
    )
      .bind(info.googleId)
      .first<User>();

    if (existing) {
      // Update profile info
      await this.env.DB.prepare(
        `UPDATE users
         SET email = ?, name = ?, avatar_url = ?, updated_at = datetime('now')
         WHERE id = ?`,
      )
        .bind(info.email, info.name, info.avatarUrl, existing.id)
        .run();

      return {
        ...existing,
        email: info.email,
        name: info.name,
        avatarUrl: info.avatarUrl,
      };
    }

    // Create new user
    const id = generateId();
    await this.env.DB.prepare(
      `INSERT INTO users (id, email, name, avatar_url, google_id)
       VALUES (?, ?, ?, ?, ?)`,
    )
      .bind(id, info.email, info.name, info.avatarUrl, info.googleId)
      .run();

    return {
      id,
      email: info.email,
      name: info.name,
      avatarUrl: info.avatarUrl,
      googleId: info.googleId,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
  }
}
