"use client";

import { Shield, LogIn, LogOut, User } from "lucide-react";
import { useAuthStore } from "@/lib/auth-store";
import { trpc, getAppUrl } from "@/lib/trpc";
import Image from "next/image";
import Link from "next/link";
import { BrandSelector } from "./brand-selector";

export function Navbar() {
  const { user, isAuthenticated, clearSession } = useAuthStore();
  const logoutMutation = trpc.auth.logout.useMutation({
    onSettled: () => {
      clearSession();
    },
  });

  const { refetch: fetchAuthUrl } = trpc.auth.getAuthUrl.useQuery(
    { redirectUri: `${getAppUrl()}/auth/callback` },
    { enabled: false },
  );
 
  async function handleLogin() {
    try {
      const { data } = await fetchAuthUrl();
      if (data?.url) {
        window.location.href = data.url;
      }
    } catch (error) {
      console.error("Failed to get auth URL:", error);
      alert("Registration/Login is currently unavailable. Please try again later.");
    }
  }

  return (
    <nav className="border-b border-surface-200 bg-white sticky top-0 z-50 shadow-sm shadow-surface-100/50">
      <div className="w-full px-2 sm:px-4 lg:px-6">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Selector Area */}
          <div className="flex items-center gap-6">
            <Link 
              href={isAuthenticated ? "/dashboard" : "/"} 
              className="flex items-center gap-3 hover:opacity-80 transition-opacity"
            >
              <div className="h-9 w-9 rounded-lg bg-brand-600 flex items-center justify-center">
                <Shield className="h-5 w-5 text-white" />
              </div>
              <div className="hidden lg:block">
                <h1 className="text-lg font-bold text-surface-900 leading-none">
                  Web Insight
                </h1>
                <p className="text-[10px] text-surface-400 font-bold uppercase tracking-widest mt-1">
                  Security Hub
                </p>
              </div>
            </Link>

            {isAuthenticated && (
              <div className="flex items-center gap-4">
                <div className="h-8 w-px bg-surface-200 hidden sm:block" />
                <div className="hidden md:flex items-center gap-1">
                  <Link 
                    href="/dashboard?mode=manage" 
                    className="px-3 py-1.5 text-[10px] font-black uppercase tracking-widest text-surface-500 hover:text-brand-600 transition-colors"
                  >
                    Portfolio
                  </Link>
                  <Link 
                    href="/dashboard?mode=quick" 
                    className="px-3 py-1.5 text-[10px] font-black uppercase tracking-widest text-surface-500 hover:text-brand-600 transition-colors"
                  >
                    Quick Audit
                  </Link>
                </div>
                <BrandSelector />
              </div>
            )}
          </div>

          {/* User area */}
          <div className="flex items-center gap-3">
            {isAuthenticated && user ? (
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2">
                  {user.avatarUrl ? (
                    <Image
                      src={user.avatarUrl}
                      alt={user.name}
                      width={32}
                      height={32}
                      className="rounded-full"
                    />
                  ) : (
                    <div className="h-8 w-8 rounded-full bg-brand-100 flex items-center justify-center">
                      <User className="h-4 w-4 text-brand-600" />
                    </div>
                  )}
                  <span className="text-sm font-medium text-surface-700 hidden sm:block">
                    {user.name}
                  </span>
                </div>
                <button
                  onClick={() => logoutMutation.mutate()}
                  className="btn-ghost gap-1.5 text-xs"
                  disabled={logoutMutation.isPending}
                >
                  <LogOut className="h-3.5 w-3.5" />
                  <span className="hidden sm:inline">Sign Out</span>
                </button>
              </div>
            ) : (
              <button
                onClick={handleLogin}
                className="btn-primary gap-2"
              >
                <LogIn className="h-4 w-4" />
                Sign in with Google
              </button>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
}
