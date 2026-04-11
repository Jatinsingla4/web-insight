import type { WsMessage } from "@dns-checker/shared";

interface ScanEvent {
  scanId: string;
  brandId: string;
  status: string;
  progress?: number;
  message?: string;
  data?: Record<string, unknown>;
}

/**
 * ScanCoordinator Durable Object
 *
 * Manages WebSocket connections for real-time scan progress updates.
 * One instance per brand — all WebSocket clients watching a brand
 * connect to the same DO instance.
 */
export class ScanCoordinator implements DurableObject {
  private readonly sessions: Map<WebSocket, { userId: string }> = new Map();
  private readonly state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;

    // Restore any hibernated WebSockets
    for (const ws of state.getWebSockets()) {
      const meta = ws.deserializeAttachment() as { userId: string } | null;
      if (meta) {
        this.sessions.set(ws, meta);
      }
    }
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // WebSocket upgrade request
    if (request.headers.get("Upgrade") === "websocket") {
      return this.handleWebSocket(request);
    }

    // Internal: scan progress update
    if (url.pathname === "/scan-progress" && request.method === "POST") {
      const event = (await request.json()) as ScanEvent;
      this.broadcast({
        type: "scan:progress",
        scanId: event.scanId,
        progress: event.progress,
        message: event.message,
      });
      return new Response("OK");
    }

    // Internal: scan complete notification
    if (url.pathname === "/scan-complete" && request.method === "POST") {
      const event = (await request.json()) as ScanEvent;
      this.broadcast({
        type:
          event.status === "completed" ? "scan:completed" : "scan:failed",
        scanId: event.scanId,
        data: event.data,
        message: event.message,
      });
      return new Response("OK");
    }

    return new Response("Not Found", { status: 404 });
  }

  private handleWebSocket(request: Request): Response {
    const url = new URL(request.url);
    const userId = url.searchParams.get("userId");

    if (!userId) {
      return new Response("Missing userId", { status: 400 });
    }

    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];

    // Accept with hibernation support
    this.state.acceptWebSocket(server);
    server.serializeAttachment({ userId });
    this.sessions.set(server, { userId });

    // Send connection confirmation
    server.send(
      JSON.stringify({
        type: "connected",
        message: "Connected to scan coordinator",
      }),
    );

    return new Response(null, { status: 101, webSocket: client });
  }

  webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): void {
    // Handle ping/pong for keepalive
    if (typeof message === "string") {
      try {
        const parsed = JSON.parse(message) as { type?: string };
        if (parsed.type === "ping") {
          ws.send(JSON.stringify({ type: "pong" }));
        }
      } catch {
        // Ignore malformed messages
      }
    }
  }

  webSocketClose(ws: WebSocket): void {
    this.sessions.delete(ws);
  }

  webSocketError(ws: WebSocket): void {
    this.sessions.delete(ws);
  }

  private broadcast(message: WsMessage): void {
    const payload = JSON.stringify(message);
    for (const [ws] of this.sessions) {
      try {
        ws.send(payload);
      } catch {
        // Client disconnected — will be cleaned up in webSocketClose
        this.sessions.delete(ws);
      }
    }
  }
}
