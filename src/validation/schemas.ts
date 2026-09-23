import { z } from 'zod';

/**
 * Every tool's raw MCP input is parsed through one of these schemas before
 * it touches any filesystem or process logic. Schemas are intentionally
 * strict: unknown keys rejected, sane bounds on sizes/lengths, no coercion
 * that could hide a type-confusion bug.
 */

const relativePathSchema = z
  .string()
  .min(1, 'path must not be empty')
  .max(4096, 'path is too long')
  .refine((p) => !p.includes('\0'), 'path must not contain null bytes');

export const listFilesSchema = z
  .object({
    path: relativePathSchema.default('.'),
    recursive: z.boolean().default(false),
    maxResults: z.number().int().positive().max(10_000).default(1000),
  })
  .strict();

export const readFileSchema = z
  .object({
    path: relativePathSchema,
    maxBytes: z.number().int().positive().max(10_000_000).optional(),
  })
  .strict();

export const searchFilesSchema = z
  .object({
    query: z.string().min(1, 'query must not be empty').max(1000, 'query is too long'),
    path: relativePathSchema.default('.'),
    caseSensitive: z.boolean().default(false),
    isRegex: z.boolean().default(false),
    maxResults: z.number().int().positive().max(10_000).default(500),
  })
  .strict();

export const getProjectInfoSchema = z.object({}).strict();

export const runCommandSchema = z
  .object({
    command: z.string().min(1, 'command must not be empty').max(256),
    args: z.array(z.string().max(4096)).max(64).default([]),
  })
  .strict();

export type ListFilesInput = z.infer<typeof listFilesSchema>;
export type ReadFileInput = z.infer<typeof readFileSchema>;
export type SearchFilesInput = z.infer<typeof searchFilesSchema>;
export type GetProjectInfoInput = z.infer<typeof getProjectInfoSchema>;
export type RunCommandInput = z.infer<typeof runCommandSchema>;

/** Parses `raw` against `schema`, returning a typed, structured result
 * instead of throwing — callers turn the failure branch into an
 * INVALID_INPUT tool error with the readable Zod message. */
export function safeValidate<T>(
  schema: z.ZodType<T>,
  raw: unknown
): { ok: true; data: T } | { ok: false; message: string } {
  const result = schema.safeParse(raw);
  if (result.success) {
    return { ok: true, data: result.data };
  }
  const message = result.error.issues
    .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`)
    .join('; ');
  return { ok: false, message };
}

/**
 * Phase 2: analyze_project takes no input beyond the configured
 * PROJECT_ROOT (same pattern as get_project_info) — analysis always runs
 * against the whole sandboxed project.
 */
export const analyzeProjectSchema = z.object({}).strict();
export type AnalyzeProjectInput = z.infer<typeof analyzeProjectSchema>;

/**
 * Phase 3: scan_project takes no input beyond PROJECT_ROOT. It performs
 * deterministic, read-only static security analysis over the authorized
 * project and returns structured findings with evidence.
 */
export const scanProjectSchema = z.object({}).strict();
export type ScanProjectInput = z.infer<typeof scanProjectSchema>;
