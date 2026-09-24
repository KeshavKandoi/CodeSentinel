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

/**
 * Phase 4: discover_routes takes no input beyond PROJECT_ROOT. It statically
 * inventories the application's externally reachable attack surface.
 */
export const discoverRoutesSchema = z.object({}).strict();
export type DiscoverRoutesInput = z.infer<typeof discoverRoutesSchema>;

/**
 * Phase 5: analyze_access_control takes no input beyond PROJECT_ROOT. It
 * runs the Phase 4 route discovery engine internally and performs
 * deterministic, read-only static access-control analysis over the
 * resulting routes.
 */
export const analyzeAccessControlSchema = z.object({}).strict();
export type AnalyzeAccessControlInput = z.infer<typeof analyzeAccessControlSchema>;


/**
 * Phase 6: verify_finding requires an explicit findingId and an explicit
 * RuntimeTarget -- there is no default target, and localhost is not
 * automatically authorized. Test sessions/credentials are supplied only
 * through this explicit input, never read from project files.
 */
export const runtimeTargetSchema = z
  .object({
    allowedOrigin: z.string().min(1).max(512),
    allowPrivateNetworkTarget: z.boolean().optional(),
    allowDestructiveMethods: z.boolean().optional(),
    vettedTestPaths: z.array(z.string().min(1).max(4096)).max(20).optional(),
    maxRequestsPerCase: z.number().int().positive().max(50).optional(),
    requestTimeoutMs: z.number().int().positive().max(30_000).optional(),
    maxResponseBytes: z.number().int().positive().max(5_000_000).optional(),
    maxRedirects: z.number().int().min(0).max(10).optional(),
    minRequestIntervalMs: z.number().int().min(0).max(10_000).optional(),
    maxConcurrency: z.number().int().positive().max(10).optional(),
  })
  .strict();

const testSessionSchema = z
  .object({
    id: z.string().min(1).max(128),
    kind: z.enum(['unauthenticated', 'authenticated']),
    headers: z.record(z.string(), z.string()).optional(),
  })
  .strict();

const sessionParamsSchema = z
  .object({
    ownerSessionId: z.string().min(1).max(128).optional(),
    otherSessionId: z.string().min(1).max(128).optional(),
    lowPrivilegedSessionId: z.string().min(1).max(128).optional(),
    authenticatedSessionId: z.string().min(1).max(128).optional(),
  })
  .strict();

export const verifyFindingSchema = z
  .object({
    findingId: z.string().min(1).max(256),
    target: runtimeTargetSchema,
    sessions: z.array(testSessionSchema).max(10).default([]),
    sessionParams: sessionParamsSchema.default({}),
  })
  .strict();
export type VerifyFindingInput = z.infer<typeof verifyFindingSchema>;

export const listVerificationCasesSchema = z.object({}).strict();
export type ListVerificationCasesInput = z.infer<typeof listVerificationCasesSchema>;

/** Phase 7: bounded, external-agent-driven investigation inputs. The agent
 * supplies reasoning and evidence references; deterministic engines remain
 * responsible for analysis and runtime safety. */
export const investigationScopeSchema = z.enum([
  'authentication',
  'authorization',
  'idor_bola',
  'input_validation',
  'secrets_exposure',
  'route_security',
  'general_application_security',
]);

export const investigationBudgetSchema = z.object({
  maxAnalysisSteps: z.number().int().refine((value) => value === 4, 'Phase 7 currently requires exactly four deterministic analysis stages.').optional(),
  maxHypotheses: z.number().int().positive().max(25).optional(),
  maxRuntimeVerifications: z.number().int().positive().max(10).optional(),
  maxElapsedMs: z.number().int().min(1_000).max(600_000).optional(),
  maxEvidenceBytes: z.number().int().min(1_000).max(1_000_000).optional(),
}).strict();

export const startSecurityInvestigationSchema = z.object({
  projectPath: z.string().min(1).max(4096),
  scope: z.array(investigationScopeSchema).min(1).max(7),
  hypothesis: z.string().min(1).max(2_000),
  budget: investigationBudgetSchema.optional(),
}).strict();

export const getInvestigationSchema = z.object({ investigationId: z.string().min(1).max(128) }).strict();

export const runSecurityAnalysisSchema = z.object({ investigationId: z.string().min(1).max(128) }).strict();

export const recordSecurityHypothesisSchema = z.object({
  investigationId: z.string().min(1).max(128),
  title: z.string().min(1).max(256),
  description: z.string().min(1).max(4_000),
  findingId: z.string().min(1).max(256).optional(),
  evidenceRefs: z.array(z.string().min(1).max(256)).min(1).max(20),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
  confidence: z.enum(['high', 'medium', 'low']).optional(),
}).strict();

export const runtimeVerificationRequestSchema = verifyFindingSchema.extend({
  investigationId: z.string().min(1).max(128),
  hypothesisId: z.string().min(1).max(128),
}).strict();

export const securityAgentInstructionsSchema = z.object({}).strict();

export type StartSecurityInvestigationInput = z.infer<typeof startSecurityInvestigationSchema>;
export type GetInvestigationInput = z.infer<typeof getInvestigationSchema>;
export type RunSecurityAnalysisInput = z.infer<typeof runSecurityAnalysisSchema>;
export type RecordSecurityHypothesisInput = z.infer<typeof recordSecurityHypothesisSchema>;
export type RuntimeVerificationRequestInput = z.infer<typeof runtimeVerificationRequestSchema>;

export const generateSecurityReportSchema = z.object({ investigationId: z.string().min(1).max(128) }).strict();
export const getSecurityFindingSchema = z.object({ investigationId: z.string().min(1).max(128), findingId: z.string().min(1).max(256) }).strict();
export type GenerateSecurityReportInput = z.infer<typeof generateSecurityReportSchema>;
export type GetSecurityFindingInput = z.infer<typeof getSecurityFindingSchema>;

const remediationFileChangeSchema = z.object({
  path: relativePathSchema,
  originalContentHash: z.string().regex(/^[a-f0-9]{64}$/, 'originalContentHash must be a SHA-256 hex digest'),
  proposedContent: z.string().max(1_000_000),
  description: z.string().min(1).max(1_000),
}).strict();

export const proposeRemediationSchema = z.object({
  investigationId: z.string().min(1).max(128),
  findingId: z.string().min(1).max(256),
  description: z.string().min(1).max(4_000),
  rationale: z.string().min(1).max(4_000),
  files: z.array(remediationFileChangeSchema).min(1).max(10),
  expectedSecurityEffect: z.string().min(1).max(2_000),
  requiresRuntimeVerification: z.boolean(),
  runtimeVerification: verifyFindingSchema.optional(),
}).strict().superRefine((value, ctx) => {
  if (value.requiresRuntimeVerification && !value.runtimeVerification) {
    ctx.addIssue({ code: 'custom', path: ['runtimeVerification'], message: 'runtimeVerification is required when requiresRuntimeVerification is true' });
  }
});
export const remediationIdSchema = z.object({ remediationId: z.string().min(1).max(128) }).strict();
export const verifyRemediationSchema = remediationIdSchema;
export const rollbackRemediationSchema = remediationIdSchema;
export type ProposeRemediationInput = z.infer<typeof proposeRemediationSchema>;
export type RemediationIdInput = z.infer<typeof remediationIdSchema>;
