"use client";

import { useEffect, useRef, useCallback, useState } from "react";
import type { WsMessage } from "@dns-checker/shared";
import { getBaseUrl } from "@/lib/trpc";
import { useAuthStore } from "@/lib/auth-store";

interface UseWebSocketOptions {
  brandId: string;
  onMessage?: (message: WsMessage) => void;
  enabled?: boolean;
}

export function useWebSocket({
  brandId,
  onMessage,
  enabled = true,
}: UseWebSocketOptions) {
  const wsRef = useRef<WebSocket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const reconnectTimeout = useRef<ReturnType<typeof setTimeout> | null>(null);
  const { user } = useAuthStore();

  const connect = useCallback(() => {
    if (!enabled || !user?.id) return;

    const baseUrl = getBaseUrl().replace(/^http/, "ws");
    const url = `${baseUrl}/ws/scan/${brandId}?userId=${user.id}`;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data as string) as WsMessage;
        onMessage?.(message);
      } catch {
        // Ignore malformed messages
      }
    };

    ws.onclose = () => {
      setIsConnected(false);
      wsRef.current = null;

      // Reconnect after 3 seconds
      if (enabled) {
        reconnectTimeout.current = setTimeout(connect, 3000);
      }
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [brandId, enabled, user?.id, onMessage]);

  useEffect(() => {
    connect();

    // Keepalive ping every 30 seconds
    const pingInterval = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: "ping" }));
      }
    }, 30_000);

    return () => {
      clearInterval(pingInterval);
      if (reconnectTimeout.current) {
        clearTimeout(reconnectTimeout.current);
      }
      wsRef.current?.close();
    };
  }, [connect]);

  return { isConnected };
}
