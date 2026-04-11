import { create } from "zustand";
import { persist } from "zustand/middleware";

interface AuthUser {
  id: string;
  email: string;
  name: string;
  avatarUrl: string | null;
}

interface AuthState {
  sessionToken: string | null;
  user: AuthUser | null;
  isAuthenticated: boolean;
  setSession: (token: string, user: AuthUser) => void;
  clearSession: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      sessionToken: null,
      user: null,
      isAuthenticated: false,

      setSession: (token, user) =>
        set({
          sessionToken: token,
          user,
          isAuthenticated: true,
        }),

      clearSession: () =>
        set({
          sessionToken: null,
          user: null,
          isAuthenticated: false,
        }),
    }),
    {
      name: "dns-checker-auth",
      partialize: (state) => ({
        sessionToken: state.sessionToken,
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    },
  ),
);
