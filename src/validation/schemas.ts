import { z } from 'zod';


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

export const analyzeProjectSchema = z.object({}).strict();
export type AnalyzeProjectInput = z.infer<typeof analyzeProjectSchema>;

export const scanProjectSchema = z.object({}).strict();
export type ScanProjectInput = z.infer<typeof scanProjectSchema>;

export const discoverRoutesSchema = z.object({}).strict();
export type DiscoverRoutesInput = z.infer<typeof discoverRoutesSchema>;

export const analyzeAccessControlSchema = z.object({}).strict();
export type AnalyzeAccessControlInput = z.infer<typeof analyzeAccessControlSchema>;


export const runtimeTargetSchema = z
  .object({
    allowedOrigin: z.string().min(1).max(512).refine((value) => { try { const parsed = new URL(value); return parsed.protocol === 'http:' || parsed.protocol === 'https:'; } catch { return false; } }, 'allowedOrigin must be an http(s) URL'),
    allowPrivateNetworkTarget: z.boolean().optional(),
    allowDestructiveMethods: z.boolean().optional(),
    vettedTestPaths: z.array(z.string().min(1).max(4096).refine((value) => value.startsWith('/') && !value.startsWith('//') && !value.includes('\\'), 'vettedTestPaths entries must be single-slash absolute paths')).max(20).optional(),
    maxRequestsPerCase: z.number().int().positive().max(50).optional(),
    requestTimeoutMs: z.number().int().positive().max(30_000).optional(),
    maxResponseBytes: z.number().int().positive().max(5_000_000).optional(),
    maxRedirects: z.number().int().min(0).max(10).optional(),
    minRequestIntervalMs: z.number().int().min(0).max(10_000).optional(),
    maxConcurrency: z.number().int().positive().max(10).optional(),
  })
  .strict();

const boundedHeaderSchema = z
  .record(z.string().min(1).max(128), z.string().max(4096).refine((value) => !/[\r\n]/.test(value), 'header values must not contain CR/LF'))
  .superRefine((headers, ctx) => {
    if (Object.keys(headers).length > 32) ctx.addIssue({ code: 'custom', message: 'too many session headers' });
    if (JSON.stringify(headers).length > 32_000) ctx.addIssue({ code: 'custom', message: 'session headers are too large' });
  });

const testSessionSchema = z
  .object({
    id: z.string().min(1).max(128),
    kind: z.enum(['unauthenticated', 'authenticated']),
    headers: boundedHeaderSchema.optional(),
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
export const remediationAuthorizationSchema = z.object({
  projectRoot: z.string().min(1).max(4096),
  localTarget: z.literal(true),
  allowRemediation: z.literal(true),
  nonProductionTestTarget: z.literal(true),
}).strict();
export const remediationIdSchema = z.object({ remediationId: z.string().min(1).max(128), authorization: remediationAuthorizationSchema }).strict();
export const applyRemediationSchema = remediationIdSchema.extend({ dryRun: z.boolean().default(false) }).strict();
export const verifyRemediationSchema = z.object({ remediationId: z.string().min(1).max(128) }).strict();
export const rollbackRemediationSchema = remediationIdSchema;
export type RemediationAuthorizationInput = z.infer<typeof remediationAuthorizationSchema>;
export const controlledRemediationSchema = z.object({
  finding: z.object({ id: z.string().min(1).max(256), file: z.string().min(1).max(4096), approval: z.enum(['confirmed', 'explicitly_approved']) }).strict(),
  authorization: remediationAuthorizationSchema.optional(),
  strategy: z.discriminatedUnion('kind', [
    z.object({ kind: z.literal('patch'), oldText: z.string().min(1).max(100_000), newText: z.string().max(100_000) }).strict(),
    z.object({ kind: z.literal('replace'), content: z.string().max(1_000_000) }).strict(),
  ]),
  dryRun: z.boolean(),
}).strict();
export const retestFindingSchema = z.object({
  findingId: z.string().min(1).max(256).regex(/^[A-Za-z0-9_.:-]+$/),
  target: runtimeTargetSchema.optional(),
  sessions: z.array(testSessionSchema).max(10).default([]),
  sessionParams: sessionParamsSchema.default({}),
}).strict();
export const securityRemediationSweepSchema = z.object({
  findingIds: z.array(z.string().min(1).max(256).regex(/^[A-Za-z0-9_.:-]+$/)).max(100).optional(),
  remediationIds: z.array(z.string().min(1).max(128).regex(/^(?:controlled-[0-9a-f-]{36}|remediation-[0-9a-f]{32})$/)).max(100).optional(),
  target: runtimeTargetSchema.optional(),
  sessions: z.array(testSessionSchema).max(10).default([]),
  sessionParams: sessionParamsSchema.default({}),
  runtimeSetupFailure: z.object({ command: z.string().max(256), output: z.string().min(1).max(8_000) }).strict().optional(),
}).strict();
export type ProposeRemediationInput = z.infer<typeof proposeRemediationSchema>;
export type RemediationIdInput = z.infer<typeof remediationIdSchema>;

import { AUDIT_FOCUSES } from '../orchestration/types.js';
import { ORCHESTRATION_ACTIONS } from '../orchestration/types.js';

export const auditLimitsSchema = z.object({
  maxSteps: z.number().int().min(1).max(100).optional(),
  maxHypotheses: z.number().int().min(1).max(25).optional(),
  maxEvidenceRefs: z.number().int().min(1).max(100).optional(),
  maxVerificationRequests: z.number().int().min(1).max(10).optional(),
  maxOutputBytes: z.number().int().min(8_000).max(200_000).optional(),
  maxElapsedMs: z.number().int().min(1_000).max(600_000).optional(),
}).strict();

export const startSecurityAuditSchema = z.object({
  objective: z.string().trim().min(1).max(1_000),
  focus: z.enum(AUDIT_FOCUSES).optional(),
  target: z.string().trim().min(1).max(256).optional(),
  limits: auditLimitsSchema.optional(),
}).strict().superRefine((value, ctx) => {
  const needsTarget = value.focus === 'route' || value.focus === 'finding';
  if (needsTarget && !value.target) ctx.addIssue({ code: 'custom', path: ['target'], message: 'target is required when focus is "route" or "finding"' });
  if (value.target && !needsTarget) ctx.addIssue({ code: 'custom', path: ['target'], message: 'target is only valid when focus is "route" or "finding"' });
});

export const auditInvestigationIdSchema = z.object({ investigationId: z.string().min(1).max(128) }).strict();

export const recordAuditHypothesisSchema = z.object({
  investigationId: z.string().min(1).max(128),
  hypothesisId: z.string().min(1).max(128).regex(/^[A-Za-z0-9_.:-]+$/, 'hypothesisId may contain letters, digits, and _ . : - only'),
  category: z.string().trim().min(1).max(64).regex(/^[A-Za-z0-9_. -]+$/, 'category may contain letters, digits, spaces, and _ . - only'),
  description: z.string().trim().min(1).max(4_000),
  affectedLocation: z.string().trim().min(1).max(512),
  reason: z.string().trim().min(1).max(2_000),
  findingId: z.string().min(1).max(256).optional(),
}).strict();

export type StartSecurityAuditInput = z.infer<typeof startSecurityAuditSchema>;
export type AuditInvestigationIdInput = z.infer<typeof auditInvestigationIdSchema>;
export type RecordAuditHypothesisInput = z.infer<typeof recordAuditHypothesisSchema>;

export const dispatchSecurityActionSchema = z.object({
  investigationId: z.string().min(1).max(128),
  action: z.enum(ORCHESTRATION_ACTIONS),
  arguments: z.record(z.string().min(1).max(128), z.unknown()).default({}).superRefine((args, ctx) => {
    if (Object.keys(args).length > 32) ctx.addIssue({ code: 'custom', message: 'too many action arguments' });
    if (JSON.stringify(args).length > 16_000) ctx.addIssue({ code: 'custom', message: 'action arguments are too large' });
  }),
}).strict();
export type DispatchSecurityActionInput = z.infer<typeof dispatchSecurityActionSchema>;

export const deepSecurityAuditSchema = z.object({
  baselinePath: relativePathSchema.optional(),
  maxFiles: z.number().int().positive().max(2_000).optional(),
}).strict();
export type DeepSecurityAuditInput = z.infer<typeof deepSecurityAuditSchema>;

export const proveSecurityFindingSchema = verifyFindingSchema;
export type ProveSecurityFindingInput = z.infer<typeof proveSecurityFindingSchema>;
export const securityGraphSchema = z.object({}).strict();

export const runFullSecurityAuditSchema = z.object({
  target: runtimeTargetSchema.optional(),
  runtimeSetupFailure: z.object({ command: z.string().max(256), output: z.string().min(1).max(8_000) }).strict().optional(),
  sessions: z.array(testSessionSchema).max(10).default([]),
  sessionParams: sessionParamsSchema.default({}),
  investigationId: z.string().min(1).max(128).optional(),
  maxFindings: z.number().int().min(1).max(500).optional(),
  maxProofAttempts: z.number().int().min(1).max(10).optional(),
  maxElapsedMs: z.number().int().min(5_000).max(600_000).optional(),
  maxFiles: z.number().int().positive().max(2_000).optional(),
  includeGraph: z.boolean().optional(),
}).strict();
export type RunFullSecurityAuditInput = z.infer<typeof runFullSecurityAuditSchema>;
