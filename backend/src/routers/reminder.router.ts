import { z } from "zod";
import { router, protectedProcedure } from "./context";
import { sslReminderInputSchema } from "@dns-checker/shared";
import { ReminderService } from "../services/reminder.service";
 
export const reminderRouter = router({
  /** Set or update an SSL expiry reminder. */
  setSslReminder: protectedProcedure
    .input(sslReminderInputSchema)
    .mutation(async ({ ctx, input }) => {
      const service = new ReminderService(ctx.env.DB);
      return service.setSslReminder(ctx.session.userId, input);
    }),
 
  /** List all reminders for the current user. */
  list: protectedProcedure.query(async ({ ctx }) => {
    const service = new ReminderService(ctx.env.DB);
    return service.listReminders(ctx.session.userId);
  }),
 
  /** Delete a reminder. */
  delete: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const service = new ReminderService(ctx.env.DB);
      return service.deleteReminder(ctx.session.userId, input.id);
    }),
});
