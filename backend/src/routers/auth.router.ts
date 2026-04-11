import { router, publicProcedure, protectedProcedure } from "./context";
import { AuthService } from "../services/auth.service";
import { generateSessionToken } from "../lib/crypto";
import { z } from "zod";

export const authRouter = router({
  /** Get the current authenticated user. */
  me: publicProcedure.query(async ({ ctx }) => {
    if (!ctx.session) return null;
    return {
      userId: ctx.session.userId,
      email: ctx.session.email,
      name: ctx.session.name,
      avatarUrl: ctx.session.avatarUrl,
    };
  }),

  /** Get Google OAuth URL. */
  getAuthUrl: publicProcedure
    .input(z.object({ redirectUri: z.string().url() }))
    .query(({ ctx, input }) => {
      const authService = new AuthService(ctx.env);
      const state = generateSessionToken();

      // Store state for CSRF protection
      ctx.waitUntil(
        ctx.env.SESSIONS.put(`oauth_state:${state}`, "1", {
          expirationTtl: 600, // 10 minutes
        }),
      );

      return {
        url: authService.getAuthUrl(input.redirectUri, state),
        state,
      };
    }),

  /** Handle OAuth callback and create session. */
  callback: publicProcedure
    .input(
      z.object({
        code: z.string().min(1),
        state: z.string().min(1),
        redirectUri: z.string().url(),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      // Verify CSRF state
      const storedState = await ctx.env.SESSIONS.get(
        `oauth_state:${input.state}`,
      );
      if (!storedState) {
        throw new Error("Invalid OAuth state — possible CSRF attack");
      }
      await ctx.env.SESSIONS.delete(`oauth_state:${input.state}`);

      const authService = new AuthService(ctx.env);
      const { sessionToken, user } = await authService.handleCallback(
        input.code,
        input.redirectUri,
      );

      return {
        sessionToken,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          avatarUrl: user.avatarUrl,
        },
      };
    }),

  /** Logout — destroy session. */
  logout: protectedProcedure.mutation(async ({ ctx }) => {
    const token = ctx.req.headers
      .get("Authorization")
      ?.replace("Bearer ", "");
    if (token) {
      const authService = new AuthService(ctx.env);
      await authService.destroySession(token);
    }
    return { success: true };
  }),
});
