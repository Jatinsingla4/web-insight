import { create } from "zustand";
import { persist } from "zustand/middleware";
import { useEffect, useState } from "react";

interface AuthUser {
  id: string;
  email: string;
  name: string;
  avatarUrl: string | null;
}

interface AuthState {
  user: AuthUser | null;
  isAuthenticated: boolean;
  setSession: (user: AuthUser) => void;
  clearSession: () => void;
}

/** True once Zustand has hydrated from localStorage — gates SSR-safe renders. */
export function useAuthHydrated(): boolean {
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => {
    // hasHydrated() returns true if the store has rehydrated from storage
    const unsub = useAuthStore.persist.onHydrate(() => setHydrated(true));
    if (useAuthStore.persist.hasHydrated()) setHydrated(true);
    return unsub;
  }, []);
  return hydrated;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      isAuthenticated: false,

      setSession: (user) =>
        set({
          user,
          isAuthenticated: true,
        }),

      clearSession: () =>
        set({
          user: null,
          isAuthenticated: false,
        }),
    }),
    {
      name: "dns-checker-auth",
      // Only persist user profile — session token lives in HttpOnly cookie
      partialize: (state) => ({
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    },
  ),
);
