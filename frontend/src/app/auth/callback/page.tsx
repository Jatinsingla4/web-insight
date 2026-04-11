"use client";

import { useEffect, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuthStore } from "@/lib/auth-store";
import { Spinner } from "@/components/ui/spinner";
import { Suspense } from "react";
import { trpc, getBaseUrl, getAppUrl } from "@/lib/trpc";

function AuthCallbackContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { setSession, clearSession } = useAuthStore();
  const hasProcessed = useRef(false);

  const callbackMutation = trpc.auth.callback.useMutation({
    onSuccess: (data) => {
      setSession(data.sessionToken, {
        id: data.user.id,
        email: data.user.email,
        name: data.user.name,
        avatarUrl: data.user.avatarUrl,
      });
      router.replace("/");
    },
    onError: (error) => {
      console.error("Auth callback failed:", error);
      clearSession();
      router.replace(`/?error=${encodeURIComponent(error.message)}`);
    },
  });

  useEffect(() => {
    if (hasProcessed.current) return;

    const code = searchParams.get("code");
    const state = searchParams.get("state");
    const error = searchParams.get("error");

    if (error) {
      hasProcessed.current = true;
      clearSession();
      router.replace(`/?error=${encodeURIComponent(error)}`);
      return;
    }

    if (code && state) {
      hasProcessed.current = true;
      callbackMutation.mutate({
        code,
        state,
        redirectUri: `${getAppUrl()}/auth/callback`,
      });
    } else if (!searchParams.has("code")) {
      // Only error out if we are sure we are not waiting for the code
      // This prevents flashing error on initial mount
      hasProcessed.current = true;
      clearSession();
      router.replace("/?error=auth_incomplete");
    }
  }, [searchParams, clearSession, router, callbackMutation]);

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
