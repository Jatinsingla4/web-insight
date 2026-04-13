import {
  createBrandSchema,
  updateBrandSchema,
  brandIdSchema,
  paginationSchema,
} from "@dns-checker/shared";
import { MAX_BRANDS_PER_USER } from "@dns-checker/shared";
import type { Brand } from "@dns-checker/shared";
import { TRPCError } from "@trpc/server";
import { router, protectedProcedure } from "./context";
import { generateId } from "../lib/crypto";
import { notFound } from "../lib/errors";
import { ScanService } from "../services/scan.service";

export const brandRouter = router({
  /** List all brands for the authenticated user. */
  list: protectedProcedure
    .input(paginationSchema)
    .query(async ({ ctx, input }) => {
      let query = `SELECT * FROM brands WHERE user_id = ?`;
      const params: unknown[] = [ctx.session.userId];

      if (input.cursor) {
        query += ` AND created_at < ?`;
        params.push(input.cursor);
      }

      query += ` ORDER BY created_at DESC LIMIT ?`;
      params.push(input.limit + 1);

      const result = await ctx.env.DB.prepare(query)
        .bind(...params)
        .all<Brand>();

      const brands = result.results ?? [];
      const hasMore = brands.length > input.limit;
      const items = brands.slice(0, input.limit).map(formatBrand);

      return {
        items,
        nextCursor: hasMore
          ? items[items.length - 1]?.createdAt
          : null,
      };
    }),

  /** Get a single brand by ID. */
  getById: protectedProcedure
    .input(brandIdSchema)
    .query(async ({ ctx, input }) => {
      const brand = await ctx.env.DB.prepare(
        `SELECT * FROM brands WHERE id = ? AND user_id = ?`,
      )
        .bind(input.id, ctx.session.userId)
        .first<Brand>();

      if (!brand) notFound("Brand");
      return formatBrand(brand);
    }),

  /** Add a new brand domain to monitor. */
  create: protectedProcedure
    .input(createBrandSchema)
    .mutation(async ({ ctx, input }) => {
      // Check brand limit
      const countResult = await ctx.env.DB.prepare(
        `SELECT COUNT(*) as count FROM brands WHERE user_id = ?`,
      )
        .bind(ctx.session.userId)
        .first<{ count: number }>();

      if ((countResult?.count ?? 0) >= MAX_BRANDS_PER_USER) {
        throw new TRPCError({
          code: "FORBIDDEN",
          message: `Maximum of ${MAX_BRANDS_PER_USER} brands allowed per account`,
        });
      }

      // Check for duplicate domain
      const existing = await ctx.env.DB.prepare(
        `SELECT id FROM brands WHERE user_id = ? AND domain = ?`,
      )
        .bind(ctx.session.userId, input.domain)
        .first();

      if (existing) {
        throw new TRPCError({
          code: "CONFLICT",
          message: "This domain is already being monitored",
        });
      }

      const id = generateId();

      await ctx.env.DB.prepare(
        `INSERT INTO brands (id, user_id, domain, name)
         VALUES (?, ?, ?, ?)`,
      )
        .bind(id, ctx.session.userId, input.domain, input.name)
        .run();

      const brand = await ctx.env.DB.prepare(
        `SELECT * FROM brands WHERE id = ?`,
      )
        .bind(id)
        .first<Brand>();

      // Handle initial scan data if provided
      const scanService = new ScanService(ctx.env);
      if (input.initialScanData) {
        await scanService.saveExistingResult(id, input.initialScanData as any);
      } else {
        // Trigger initial scan in background — pass ctx so SSL deep scan can use waitUntil
        ctx.waitUntil(
          (async () => {
            try {
              await scanService.brandScan(id, input.domain, undefined, ctx);
            } catch {
              // Initial scan failure is non-critical
            }
          })(),
        );
      }

      return formatBrand(brand);
    }),

  /** Update a brand's details. */
  update: protectedProcedure
    .input(updateBrandSchema)
    .mutation(async ({ ctx, input }) => {
      const brand = await ctx.env.DB.prepare(
        `SELECT * FROM brands WHERE id = ? AND user_id = ?`,
      )
        .bind(input.id, ctx.session.userId)
        .first<Brand>();
 
      if (!brand) notFound("Brand");
 
      const name = input.name ?? brand.name;
      const domain = input.domain ?? brand.domain;
      const domainChanged = input.domain && input.domain !== brand.domain;
 
      await ctx.env.DB.prepare(
        `UPDATE brands 
         SET name = ?, domain = ?, updated_at = datetime('now') 
         WHERE id = ?`,
      )
        .bind(name, domain, input.id)
        .run();
 
      // If domain changed, trigger a fresh scan immediately — pass ctx for SSL deep scan
      if (domainChanged) {
        ctx.waitUntil(
          (async () => {
            try {
              const scanService = new ScanService(ctx.env);
              await scanService.brandScan(input.id, domain, undefined, ctx);
            } catch (err) {
              console.error(`Failed to trigger refresh scan for brand ${input.id}:`, err);
            }
          })(),
        );
      }
 
      return formatBrand({
        ...brand,
        name,
        domain,
      });
    }),

  /** Delete a brand and all associated scans. */
  delete: protectedProcedure
    .input(brandIdSchema)
    .mutation(async ({ ctx, input }) => {
      const brand = await ctx.env.DB.prepare(
        `SELECT * FROM brands WHERE id = ? AND user_id = ?`,
      )
        .bind(input.id, ctx.session.userId)
        .first<Brand>();

      if (!brand) notFound("Brand");

      // Clean up R2 objects in background
      ctx.waitUntil(
        (async () => {
          const scans = await ctx.env.DB.prepare(
            `SELECT raw_response_r2_key FROM scans
             WHERE brand_id = ? AND raw_response_r2_key IS NOT NULL`,
          )
            .bind(input.id)
            .all<{ raw_response_r2_key: string }>();

          const keys = (scans.results ?? []).map(
            (s) => s.raw_response_r2_key,
          );
          for (const key of keys) {
            await ctx.env.R2.delete(key);
          }
        })(),
      );

      // CASCADE will handle scans deletion
      await ctx.env.DB.prepare(`DELETE FROM brands WHERE id = ?`)
        .bind(input.id)
        .run();

      return { success: true };
    }),
});

function formatBrand(row: any): Brand {
  return {
    id: row.id,
    userId: row.user_id,
    domain: row.domain,
    name: row.name,
    lastScanId: row.last_scan_id ?? null,
    lastScannedAt: row.last_scanned_at ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}
