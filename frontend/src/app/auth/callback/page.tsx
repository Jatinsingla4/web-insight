"use client";

import { useEffect, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuthStore } from "@/lib/auth-store";
import { Spinner } from "@/components/ui/spinner";
import { Suspense } from "react";

function AuthCallbackContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { setSession, clearSession } = useAuthStore();
  const hasProcessed = useRef(false);

  useEffect(() => {
    if (hasProcessed.current) return;
    hasProcessed.current = true;

    const error = searchParams.get("error");
    if (error) {
      clearSession();
      router.replace(`/?error=${encodeURIComponent(error)}`);
      return;
    }

    // Backend sets HttpOnly cookie and redirects here with user profile in URL params
    const userId = searchParams.get("userId");
    const name = searchParams.get("name");
    const email = searchParams.get("email");

    if (userId && name && email) {
      setSession({
        id: userId,
        email,
        name,
        avatarUrl: null, // fetched from trpc.auth.me on next load if needed
      });
      router.replace("/dashboard");
    } else {
      clearSession();
      router.replace("/?error=auth_incomplete");
    }
  }, [searchParams, setSession, clearSession, router]);

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <Spinner size="lg" />
        <p className="mt-4 text-sm text-surface-500">
          Completing sign in...
        </p>
      </div>
    </div>
  );
}

export default function AuthCallbackPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen flex items-center justify-center">
          <Spinner size="lg" />
        </div>
      }
    >
      <AuthCallbackContent />
    </Suspense>
  );
}
