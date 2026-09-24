import { z } from 'zod';
import type { McpToolResponse, ToolDefinition } from '../tools/registry.js';
import type { ToolOutcome } from '../types.js';
import { auditInvestigationIdSchema, recordAuditHypothesisSchema, runtimeVerificationRequestSchema, startSecurityAuditSchema } from '../validation/schemas.js';
import {
  completeSecurityAudit, generateSecurityAuditReport, getSecurityAuditState, planSecurityInvestigation,
  recordAuditHypothesis, requestAuditVerification, runAuditAnalysis, startSecurityAudit,
} from './engine.js';

function respond<T>(outcome: ToolOutcome<T>): McpToolResponse {
  if (outcome.ok) return { content: [{ type: 'text', text: JSON.stringify(outcome.data, null, 2) }], isError: false };
  return { content: [{ type: 'text', text: JSON.stringify({ error: outcome.error.code, message: outcome.error.message }, null, 2) }], isError: true };
}

function invalid(message: string): McpToolResponse {
  return { content: [{ type: 'text', text: JSON.stringify({ error: 'INVALID_INPUT', message }, null, 2) }], isError: true };
}

function validate<S extends z.ZodType>(schema: S, raw: unknown): { ok: true; data: z.infer<S> } | { ok: false; message: string } {
  const parsed = schema.safeParse(raw ?? {});
  if (parsed.success) return { ok: true, data: parsed.data };
  return { ok: false, message: parsed.error.issues.map((i) => `${i.path.join('.') || 'input'}: ${i.message}`).join('; ') };
}

const idProps = { type: 'object', properties: { investigationId: { type: 'string' } }, required: ['investigationId'] };

export const orchestrationToolDefinitions: ToolDefinition[] = [
  {
    name: 'start_security_audit',
    description: 'Create a bounded security audit session from a security objective. The objective is what to review, not a finding. The external AI reasons; CodeSentinel executes deterministically and enforces limits.',
    inputSchema: { type: 'object', properties: { objective: { type: 'string' }, focus: { type: 'string' }, target: { type: 'string' }, limits: { type: 'object' } }, required: ['objective'] },
    handler: async (config, raw) => {
      const v = validate(startSecurityAuditSchema, raw);
      return v.ok ? respond(startSecurityAudit(config, v.data)) : invalid(v.message);
    },
  },
  {
    name: 'plan_security_investigation',
    description: 'Return a deterministic list of CodeSentinel capabilities relevant to the audit objective. A capability plan only, not a security conclusion and no LLM planner. Moves the audit from created to planning.',
    inputSchema: idProps,
    handler: async (_config, raw) => {
      const v = validate(auditInvestigationIdSchema, raw);
      return v.ok ? respond(planSecurityInvestigation(v.data.investigationId)) : invalid(v.message);
    },
  },
  {
    name: 'get_security_audit_state',
    description: 'Return the bounded, redacted, deterministic audit state: objective, status, capabilities, steps, hypotheses, evidence references, findings, verification results, blocked operations, errors, and remaining work.',
    inputSchema: idProps,
    handler: async (_config, raw) => {
      const v = validate(auditInvestigationIdSchema, raw);
      return v.ok ? respond(getSecurityAuditState(v.data.investigationId)) : invalid(v.message);
    },
  },
  {
    name: 'run_audit_analysis',
    description: 'Execute the existing deterministic analysis pipeline (project discovery, static scan, route discovery, access-control analysis) once through the audit and record it as a traceable step.',
    inputSchema: idProps,
    handler: async (config, raw) => {
      const v = validate(auditInvestigationIdSchema, raw);
      return v.ok ? respond(await runAuditAnalysis(config, v.data.investigationId)) : invalid(v.message);
    },
  },
  {
    name: 'record_audit_hypothesis',
    description: 'Record an unverified hypothesis (id, category, description, affected location, reason). Hypotheses are never evidence and never confirmed findings; they cannot mark anything verified.',
    inputSchema: { type: 'object', properties: { investigationId: { type: 'string' }, hypothesisId: { type: 'string' }, category: { type: 'string' }, description: { type: 'string' }, affectedLocation: { type: 'string' }, reason: { type: 'string' }, findingId: { type: 'string' } }, required: ['investigationId', 'hypothesisId', 'category', 'description', 'affectedLocation', 'reason'] },
    handler: async (_config, raw) => {
      const v = validate(recordAuditHypothesisSchema, raw);
      return v.ok ? respond(recordAuditHypothesis(v.data)) : invalid(v.message);
    },
  },
  {
    name: 'request_audit_verification',
    description: 'Ask the existing Phase 6 runtime verifier to test one audit hypothesis. CodeSentinel independently enforces target authorization, limits, and session rules; rejected attempts count toward the limit.',
    inputSchema: { type: 'object', properties: { investigationId: { type: 'string' }, hypothesisId: { type: 'string' }, findingId: { type: 'string' }, target: { type: 'object' }, sessions: { type: 'array' }, sessionParams: { type: 'object' } }, required: ['investigationId', 'hypothesisId', 'findingId', 'target'] },
    handler: async (config, raw) => {
      const v = validate(runtimeVerificationRequestSchema, raw);
      return v.ok ? respond(await requestAuditVerification(config, v.data)) : invalid(v.message);
    },
  },
  {
    name: 'complete_security_audit',
    description: 'Mark the audit completed only when all required deterministic work has finished; otherwise return INVESTIGATION_INCOMPLETE with the remaining work.',
    inputSchema: idProps,
    handler: async (_config, raw) => {
      const v = validate(auditInvestigationIdSchema, raw);
      return v.ok ? respond(completeSecurityAudit(v.data.investigationId)) : invalid(v.message);
    },
  },
  {
    name: 'generate_security_audit_report',
    description: 'For a completed audit, produce the existing Phase 8 security report plus a traceability map (finding to evidence to investigation step to audit step). Does not modify any source file.',
    inputSchema: idProps,
    handler: async (_config, raw) => {
      const v = validate(auditInvestigationIdSchema, raw);
      return v.ok ? respond(await generateSecurityAuditReport(v.data.investigationId)) : invalid(v.message);
    },
  },
];
