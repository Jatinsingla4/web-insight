import {
  quickScanInputSchema,
  rescanInputSchema,
  scanHistoryInputSchema,
  brandIdSchema,
  compareScansSchema,
  sslStatusInputSchema,
} from "@dns-checker/shared";
import type { ScanResult, SslCertificate, Scan } from "@dns-checker/shared";
import { router, rateLimitedProcedure, protectedProcedure } from "./context";
import { ScanService } from "../services/scan.service";
import { notFound } from "../lib/errors";

export const scanRouter = router({
  /** Stateless quick scan — no auth required. */
  quick: rateLimitedProcedure
    .input(quickScanInputSchema)
    .mutation(async ({ ctx, input }): Promise<ScanResult> => {
      const scanService = new ScanService(ctx.env);
      // Always force a fresh scan for the quick tool
      return scanService.quickScan(input.url, undefined, true, ctx);
    }),

  /** Lightweight SSL deep scan status poll — just reads KV, no computation. */
  sslStatus: rateLimitedProcedure
    .input(sslStatusInputSchema)
    .query(async ({ ctx, input }): Promise<SslCertificate | null> => {
      const cacheKey = `ssl:sentinel:v3:${input.domain}`;
      return ctx.env.CACHE.get<SslCertificate>(cacheKey, "json");
    }),

  /** Trigger a brand rescan — requires auth. */
  rescan: protectedProcedure
    .input(rescanInputSchema)
    .mutation(async ({ ctx, input }): Promise<{ scanId: string }> => {
      // Verify ownership
      const brand = await ctx.env.DB.prepare(
        `SELECT * FROM brands WHERE id = ? AND user_id = ?`,
      )
        .bind(input.brandId, ctx.session.userId)
        .first();

      if (!brand) notFound("Brand");

      const scanService = new ScanService(ctx.env);

      // Dispatch scan via Durable Object for real-time updates
      const doId = ctx.env.SCAN_COORDINATOR.idFromName(input.brandId);
      const stub = ctx.env.SCAN_COORDINATOR.get(doId);

      const scanId = await scanService.brandScan(
        input.brandId,
        brand.domain as string,
        undefined,
        ctx
      );

      // Notify the DO that scan completed
      ctx.waitUntil(
        stub.fetch(
          new Request("https://internal/scan-complete", {
            method: "POST",
            body: JSON.stringify({
              scanId,
              brandId: input.brandId,
              status: "completed",
            }),
          }),
        ),
      );

      return { scanId };
    }),

  /** Get a single scan result. */
  getById: protectedProcedure
    .input(brandIdSchema.extend({ scanId: brandIdSchema.shape.id }))
    .query(async ({ ctx, input }) => {
      const scan = await ctx.env.DB.prepare(
        `SELECT s.* FROM scans s
         JOIN brands b ON s.brand_id = b.id
         WHERE s.id = ? AND b.user_id = ?`,
      )
        .bind(input.scanId, ctx.session.userId)
        .first<Scan>();

      if (!scan) notFound("Scan");
      return formatScan(scan);
    }),

  /** Get scan history for a brand. */
  history: protectedProcedure
    .input(scanHistoryInputSchema)
    .query(async ({ ctx, input }) => {
      // Verify ownership
      const brand = await ctx.env.DB.prepare(
        `SELECT id FROM brands WHERE id = ? AND user_id = ?`,
      )
        .bind(input.brandId, ctx.session.userId)
        .first();

      if (!brand) notFound("Brand");

      let query = `SELECT * FROM scans WHERE brand_id = ?`;
      const params: unknown[] = [input.brandId];

      if (input.cursor) {
        query += ` AND created_at < ?`;
        params.push(input.cursor);
      }

      query += ` ORDER BY created_at DESC LIMIT ?`;
      params.push(input.limit + 1);

      const result = await ctx.env.DB.prepare(query)
        .bind(...params)
        .all<Scan>();

      const scans = result.results ?? [];
      const hasMore = scans.length > input.limit;
      const items = scans.slice(0, input.limit).map(formatScan);

      return {
        items,
        nextCursor: hasMore
          ? items[items.length - 1]?.createdAt
          : null,
      };
    }),

  /** Get raw scan data from R2. */
  rawData: protectedProcedure
    .input(brandIdSchema.extend({ scanId: brandIdSchema.shape.id }))
    .query(async ({ ctx, input }) => {
      const scan = await ctx.env.DB.prepare(
        `SELECT s.raw_response_r2_key FROM scans s
         JOIN brands b ON s.brand_id = b.id
         WHERE s.id = ? AND b.user_id = ?`,
      )
        .bind(input.scanId, ctx.session.userId)
        .first<{ raw_response_r2_key: string | null }>();

      if (!scan?.raw_response_r2_key) notFound("Raw scan data");

      const object = await ctx.env.R2.get(scan.raw_response_r2_key);
      if (!object) notFound("Raw scan data");

      return (await object.json()) as ScanResult;
    }),

  /** Get the latest scan result for a brand. */
  getLatest: protectedProcedure
    .input(brandIdSchema)
    .query(async ({ ctx, input }) => {
      // Get the latest COMPLETED scan — skip "running" scans that have no data yet
      const scan = await ctx.env.DB.prepare(
        `SELECT s.id, s.raw_response_r2_key FROM scans s
         JOIN brands b ON s.brand_id = b.id
         WHERE s.brand_id = ? AND b.user_id = ? AND s.status = 'completed'
         ORDER BY s.created_at DESC LIMIT 1`,
      )
        .bind(input.id, ctx.session.userId)
        .first<{ id: string; raw_response_r2_key: string | null }>();

      if (!scan) return null;

      if (!scan.raw_response_r2_key) {
        // Fallback to DB fields if R2 key is missing
        const fullScan = await ctx.env.DB.prepare(
          `SELECT s.*, b.domain FROM scans s
           JOIN brands b ON s.brand_id = b.id
           WHERE s.id = ?`,
        )
          .bind(scan.id)
          .first<Scan & { domain: string }>();

        if (!fullScan) return null;

        const formatted = formatScan(fullScan);
        return {
          ...formatted,
          id: fullScan.id,
          url: `https://${fullScan.domain}`,
          domain: fullScan.domain,
          scannedAt: fullScan.created_at,
          techStack: formatted.techStack ?? [],
          dns: formatted.dns ?? { records: [], nameservers: [] },
          ssl: formatted.ssl ?? null,
        } as any; // Cast as any for now to satisfy complex union, or refine ScanResult type
      }

      const object = await ctx.env.R2.get(scan.raw_response_r2_key);
      if (!object) return null;

      const data = (await object.json()) as ScanResult;
      return {
        ...data,
        id: scan.id,
      };
    }),

  /** Get two scans for comparison reporting. Supports custom ID selection. */
  compare: protectedProcedure
    .input(compareScansSchema)
    .query(async ({ ctx, input }) => {
      let latestRef: { id: string; raw_response_r2_key: string | null } | null = null;
      let previousRef: { id: string; raw_response_r2_key: string | null } | null = null;

      if (input.currentScanId) {
        // Fetch specific current scan
        latestRef = await ctx.env.DB.prepare(
          `SELECT s.id, s.raw_response_r2_key FROM scans s
           JOIN brands b ON s.brand_id = b.id
           WHERE s.id = ? AND b.user_id = ?`,
        )
          .bind(input.currentScanId, ctx.session.userId)
          .first();
      }

      if (input.previousScanId) {
        // Fetch specific previous scan
        previousRef = await ctx.env.DB.prepare(
          `SELECT s.id, s.raw_response_r2_key FROM scans s
           JOIN brands b ON s.brand_id = b.id
           WHERE s.id = ? AND b.user_id = ?`,
        )
          .bind(input.previousScanId, ctx.session.userId)
          .first();
      }

      // If either is still missing, fallback to latest logic
      if (!latestRef || !previousRef) {
        const scans = await ctx.env.DB.prepare(
          `SELECT s.id, s.raw_response_r2_key FROM scans s
           JOIN brands b ON s.brand_id = b.id
           WHERE s.brand_id = ? AND b.user_id = ?
           ORDER BY s.created_at DESC LIMIT 2`,
        )
          .bind(input.brandId, ctx.session.userId)
          .all<{ id: string; raw_response_r2_key: string | null }>();

        if (!scans.results || scans.results.length === 0) return null;

        if (!latestRef) latestRef = scans.results[0];
        if (!previousRef) previousRef = scans.results[1] ?? null;
      }

      const fetchScanData = async (ref: { id: string; raw_response_r2_key: string | null }) => {
        if (!ref.raw_response_r2_key) return null;
        const object = await ctx.env.R2.get(ref.raw_response_r2_key);
        if (!object) return null;
        const data = (await object.json()) as ScanResult;
        return {
          ...data,
          id: ref.id,
        };
      };

      const [current, previous] = await Promise.all([
        fetchScanData(latestRef),
        previousRef ? fetchScanData(previousRef) : Promise.resolve(null),
      ]);

      if (!current) return null;

      return {
        current,
        previous,
      };
    }),
});

function formatScan(scan: Scan) {
  const extraData = scan.extra_data_json ? JSON.parse(scan.extra_data_json) : {};
  return {
    ...scan,
    ...extraData,
    createdAt: scan.created_at,
    startedAt: scan.started_at,
    completedAt: scan.completed_at,
    techStack: scan.tech_stack_json ? JSON.parse(scan.tech_stack_json) : null,
    dns: scan.dns_json ? JSON.parse(scan.dns_json) : null,
    ssl: scan.ssl_json ? JSON.parse(scan.ssl_json) : null,
  };
}
