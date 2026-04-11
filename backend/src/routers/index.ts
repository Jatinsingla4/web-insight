import { router } from "./context";
import { scanRouter } from "./scan.router";
import { brandRouter } from "./brand.router";
import { authRouter } from "./auth.router";
import { reminderRouter } from "./reminder.router";

export const appRouter = router({
  scan: scanRouter,
  brand: brandRouter,
  auth: authRouter,
  reminder: reminderRouter,
});

export type AppRouter = typeof appRouter;
