import crypto from 'node:crypto';
import path from 'node:path';
import type { AppConfig } from '../config.js';
import { runProjectDiscovery } from '../discovery/projectDiscovery.js';
import { scanProject } from '../security/scanner.js';
import { discoverRoutes } from '../routes/engine.js';
import { analyzeAccessControl } from '../access/engine.js';
import { verifyFinding } from '../runtime/engine.js';
import type { VerifyFindingRequest } from '../runtime/engine.js';
import { err, ok, type ToolOutcome } from '../types.js';
import type {
  InvestigationBudget,
  InvestigationEvidence,
  InvestigationFinding,
  InvestigationInternals,
  InvestigationScope,
  InvestigationStep,
  InvestigationRuntimeResult,
  SecurityHypothesis,
  SecurityInvestigation,
} from './types.js';

const DEFAULT_BUDGET: InvestigationBudget = {
  maxAnalysisSteps: 4,
  maxHypotheses: 10,
  maxRuntimeVerifications: 5,
  maxElapsedMs: 120_000,
  maxEvidenceBytes: 100_000,
};

const investigations = new Map<string, InvestigationInternals>();
const investigationLocks = new Map<string, Promise<void>>();
const MAX_STORED_INVESTIGATIONS = 100;

function id(prefix: string): string {
  return `${prefix}-${crypto.randomUUID()}`;
}

function now(): string {
  return new Date().toISOString();
}

function boundedBudget(budget?: Partial<InvestigationBudget>): InvestigationBudget {
  const merged = { ...DEFAULT_BUDGET, ...(budget ?? {}) };
  if (
    merged.maxAnalysisSteps < 4 || merged.maxAnalysisSteps > 4 ||
    merged.maxHypotheses < 1 || merged.maxHypotheses > 25 ||
    merged.maxRuntimeVerifications < 1 || merged.maxRuntimeVerifications > 10 ||
    merged.maxElapsedMs < 1_000 || merged.maxElapsedMs > 600_000 ||
    merged.maxEvidenceBytes < 1_000 || merged.maxEvidenceBytes > 1_000_000
  ) throw new Error('Investigation budget is outside the supported bounds.');
  return merged;
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function boundary(config: AppConfig, projectPath: string): string | null {
  const requested = path.resolve(projectPath);
  const configured = path.resolve(config.projectRoot);
  return requested === configured ? null : `Project path must equal the configured project root; access to "${projectPath}" is outside the authorized investigation boundary.`;
}

function get(idValue: string): InvestigationInternals | null {
  return investigations.get(idValue) ?? null;
}

async function withInvestigationLock<T>(investigationId: string, operation: () => Promise<T>): Promise<T> {
  const previous = investigationLocks.get(investigationId) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => { release = resolve; });
  investigationLocks.set(investigationId, current);
  await previous;
  try {
    return await operation();
  } finally {
    release();
    if (investigationLocks.get(investigationId) === current) investigationLocks.delete(investigationId);
  }
}

function operationKey(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, ' ');
}

function checkTime(state: InvestigationInternals): string | null {
  if (Date.now() - Date.parse(state.investigation.createdAt) > state.investigation.budget.maxElapsedMs) {
    state.investigation.status = 'blocked';
    state.investigation.updatedAt = now();
    return 'Investigation elapsed-time budget exceeded.';
  }
  return null;
}

function addEvidence(state: InvestigationInternals, evidence: Omit<InvestigationEvidence, 'id' | 'capturedAt'>): string {
  const projected = state.investigation.execution.evidenceBytes + Buffer.byteLength(JSON.stringify(evidence), 'utf8');
  if (projected > state.investigation.budget.maxEvidenceBytes) throw new Error('Investigation evidence budget exceeded.');
  const evidenceId = id('evidence');
  state.investigation.evidence.push({ ...evidence, id: evidenceId, capturedAt: now() });
  state.investigation.execution.evidenceBytes = projected;
  return evidenceId;
}

function addStep(state: InvestigationInternals, operation: InvestigationStep['operation'], summary: string, evidenceRefs: string[]): void {
  const startedAt = now();
  state.investigation.steps.push({ id: id('step'), operation, status: 'completed', startedAt, finishedAt: now(), summary, evidenceRefs });
}

function createFindingView(finding: { id: string; title: string; severity: InvestigationFinding['severity']; confidence: InvestigationFinding['confidence']; verificationStatus: string }): InvestigationFinding {
  return { findingId: finding.id, title: finding.title, staticStatus: 'suspected', severity: finding.severity, confidence: finding.confidence, lifecycle: 'static_candidate', runtimeVerificationStatus: finding.verificationStatus };
}

export function startInvestigation(
  config: AppConfig,
  input: { projectPath: string; scope: InvestigationScope[]; hypothesis: string; budget?: Partial<InvestigationBudget> }
): ToolOutcome<SecurityInvestigation> {
  const blocked = boundary(config, input.projectPath);
  if (blocked) return err('PROJECT_BOUNDARY', blocked);
  let budget: InvestigationBudget;
  try { budget = boundedBudget(input.budget); } catch (e) { return err('INVALID_INPUT', (e as Error).message); }
  const timestamp = now();
  if (investigations.size >= MAX_STORED_INVESTIGATIONS) {
    const removable = [...investigations.values()]
      .filter((item) => ['completed', 'failed', 'blocked'].includes(item.investigation.status))
      .sort((a, b) => a.investigation.updatedAt.localeCompare(b.investigation.updatedAt))[0];
    if (!removable) return err('BUDGET_EXCEEDED', 'The bounded investigation store is full; complete or remove an existing investigation before starting another.');
    investigations.delete(removable.investigation.id);
    investigationLocks.delete(removable.investigation.id);
  }
  const investigation: SecurityInvestigation = {
    id: id('investigation'), projectPath: path.resolve(input.projectPath), scope: input.scope,
    status: 'created', hypothesis: input.hypothesis, steps: [], evidence: [], hypotheses: [], findings: [], runtimeResults: {}, analysis: null,
    budget, execution: { analysisSteps: 0, runtimeVerifications: 0, evidenceBytes: 0, operations: [] }, createdAt: timestamp, updatedAt: timestamp,
  };
  investigations.set(investigation.id, { investigation, accessFindings: [], routes: [], securityFindings: [], runtimeResults: new Map() });
  return ok(investigation);
}

export async function runSecurityAnalysis(config: AppConfig, investigationId: string): Promise<ToolOutcome<SecurityInvestigation>> {
  return withInvestigationLock(investigationId, async () => {
    const state = get(investigationId);
    if (!state) return err('INVESTIGATION_NOT_FOUND', `Investigation "${investigationId}" was not found.`);
    if (state.investigation.execution.operations.includes('static-analysis')) return ok(state.investigation);
    if (state.investigation.status !== 'created') return err('INVALID_TRANSITION', `Static analysis cannot start from status "${state.investigation.status}".`);
    const elapsed = checkTime(state);
    if (elapsed) return err('BUDGET_EXCEEDED', elapsed);
    state.investigation.status = 'running';
    state.investigation.execution.operations.push('static-analysis');
    try {
      const profile = runProjectDiscovery(config.projectRoot);
      state.investigation.execution.analysisSteps = 1;
      if (checkTime(state)) return err('BUDGET_EXCEEDED', 'Investigation elapsed-time budget exceeded after project discovery.');
      const scan = await scanProject(config);
      state.investigation.execution.analysisSteps = 2;
      if (checkTime(state)) return err('BUDGET_EXCEEDED', 'Investigation elapsed-time budget exceeded after static scanning.');
      const routes = discoverRoutes(config);
      if (!routes.ok) throw new Error(routes.error.message);
      state.investigation.execution.analysisSteps = 3;
      if (checkTime(state)) return err('BUDGET_EXCEEDED', 'Investigation elapsed-time budget exceeded after route discovery.');
      const access = analyzeAccessControl(config, routes.data.entries);
      state.investigation.execution.analysisSteps = 4;
      if (checkTime(state)) return err('BUDGET_EXCEEDED', 'Investigation elapsed-time budget exceeded after access-control analysis.');
      state.securityFindings = scan.ok ? scan.data.findings : [];
      state.routes = routes.data.entries;
      state.accessFindings = access.findings;
      const scanRefs = state.securityFindings.map((finding) => `securityFinding:${finding.id}`);
      const routeRefs = state.routes.map((entry) => `route:${entry.id}`);
      const accessRefs = state.accessFindings.map((finding) => `accessFinding:${finding.id}`);
      for (const finding of state.securityFindings) addEvidence(state, { kind: 'security_finding', reference: `securityFinding:${finding.id}`, summary: `${finding.title} (${finding.severity}, ${finding.confidence}).` });
      for (const entry of state.routes) addEvidence(state, { kind: 'route', reference: `route:${entry.id}`, summary: `${entry.method} ${entry.path} (${entry.framework}).` });
      for (const finding of state.accessFindings) addEvidence(state, { kind: 'access_finding', reference: `accessFinding:${finding.id}`, summary: `${finding.title} on ${finding.method} ${finding.path}.` });
      const projectRef = addEvidence(state, { kind: 'project', reference: 'project', summary: `${profile.projectName ?? 'Unnamed project'} (${profile.ecosystem}).` });
      addStep(state, 'project_discovery', 'Project profile collected.', [projectRef]);
      addStep(state, 'static_analysis', `Static scanner produced ${state.securityFindings.length} findings.`, scanRefs);
      addStep(state, 'route_discovery', `Route discovery produced ${state.routes.length} entries.`, routeRefs);
      addStep(state, 'access_control_analysis', `Access-control analysis produced ${state.accessFindings.length} findings.`, accessRefs);
      state.investigation.analysis = {
        project: { name: profile.projectName, ecosystem: profile.ecosystem },
        scan: { total: scan.ok ? scan.data.findings.length : 0, findingIds: state.securityFindings.map((f) => f.id), warningCount: scan.ok ? scan.data.warnings.length : 1 },
        routes: { total: state.routes.length, routeIds: state.routes.map((e) => e.id), warningCount: routes.data.warnings.length },
        accessControl: { totalRoutes: access.summary.totalRoutes, totalFindings: access.findings.length, findingIds: access.findings.map((f) => f.id), warningCount: access.warnings.length },
      };
      state.investigation.findings = state.accessFindings.map(createFindingView);
      state.investigation.status = state.accessFindings.length > 0 ? 'awaiting_verification' : 'completed';
      state.investigation.updatedAt = now();
      return ok(state.investigation);
    } catch (error) {
      const message = error instanceof Error ? error.message : '';
      if (/budget/i.test(message)) {
        state.investigation.status = 'blocked';
        state.investigation.updatedAt = now();
        return err('BUDGET_EXCEEDED', 'Investigation budget was exhausted during deterministic analysis.');
      }
      state.investigation.status = 'failed';
      state.investigation.updatedAt = now();
      return err('ANALYSIS_FAILED', 'Deterministic security analysis failed unexpectedly.');
    }
  });
}

export async function recordHypothesis(config: AppConfig, input: { investigationId: string; title: string; description: string; findingId?: string; evidenceRefs: string[]; severity?: SecurityHypothesis['severity']; confidence?: SecurityHypothesis['confidence'] }): Promise<ToolOutcome<SecurityHypothesis>> {
  return withInvestigationLock(input.investigationId, async () => {
    const state = get(input.investigationId);
    if (!state) return err('INVESTIGATION_NOT_FOUND', `Investigation "${input.investigationId}" was not found.`);
    if (state.investigation.status !== 'awaiting_verification') return err('INVALID_TRANSITION', `A hypothesis cannot be recorded from status "${state.investigation.status}".`);
    const elapsed = checkTime(state);
    if (elapsed) return err('BUDGET_EXCEEDED', elapsed);
    if (state.investigation.hypotheses.length >= state.investigation.budget.maxHypotheses) return err('BUDGET_EXCEEDED', 'Maximum hypotheses for this investigation has been reached.');
    const key = operationKey(`${input.investigationId}|hypothesis|${input.title}|${input.findingId ?? ''}|${[...input.evidenceRefs].sort().join('|')}`);
    if (state.investigation.execution.operations.includes(`hypothesis:${key}`)) return err('DUPLICATE_OPERATION', 'An identical hypothesis has already been recorded.');
    if (input.evidenceRefs.length === 0) return err('HYPOTHESIS_INVALID', 'A hypothesis must contain at least one evidence reference.');
    const available = new Set(state.investigation.evidence.flatMap((e) => [e.id, e.reference]));
    const missing = input.evidenceRefs.filter((ref) => !available.has(ref));
    if (missing.length > 0) return err('HYPOTHESIS_INVALID', `Evidence references are not available: ${missing.join(', ')}.`);
    if (input.findingId) {
      if (!state.accessFindings.some((finding) => finding.id === input.findingId)) return err('HYPOTHESIS_INVALID', `Finding "${input.findingId}" is not part of this investigation.`);
      const matchingEvidence = state.investigation.evidence.some(
        (e) => (input.evidenceRefs.includes(e.id) && e.reference === `accessFinding:${input.findingId}`) || input.evidenceRefs.includes(`accessFinding:${input.findingId}`)
      );
      if (!matchingEvidence) return err('HYPOTHESIS_INVALID', 'A finding-backed hypothesis must reference the matching access-control evidence item.');
    }
    const hypothesis: SecurityHypothesis = { id: id('hypothesis'), title: input.title, description: input.description, findingId: input.findingId ?? null, evidenceRefs: [...input.evidenceRefs], severity: input.severity ?? null, confidence: input.confidence ?? null, status: 'open', createdAt: now() };
    state.investigation.hypotheses.push(hypothesis);
    state.investigation.execution.operations.push(`hypothesis:${key}`);
    addStep(state, 'hypothesis', hypothesis.title, input.evidenceRefs);
    state.investigation.updatedAt = now();
    return ok(hypothesis);
  });
}

export async function requestRuntimeVerification(config: AppConfig, input: VerifyFindingRequest & { investigationId: string; hypothesisId: string }): Promise<ToolOutcome<SecurityInvestigation>> {
  return withInvestigationLock(input.investigationId, async () => {
    const state = get(input.investigationId);
    if (!state) return err('INVESTIGATION_NOT_FOUND', `Investigation "${input.investigationId}" was not found.`);
    if (state.investigation.status !== 'awaiting_verification') return err('INVALID_TRANSITION', `Runtime verification cannot start from status "${state.investigation.status}".`);
    const hypothesis = state.investigation.hypotheses.find((item) => item.id === input.hypothesisId);
    if (!hypothesis) return err('HYPOTHESIS_NOT_FOUND', `Hypothesis "${input.hypothesisId}" was not found in this investigation.`);
    if (!hypothesis.findingId || hypothesis.findingId !== input.findingId || hypothesis.evidenceRefs.length === 0) return err('HYPOTHESIS_INVALID', 'Runtime verification must reference the evidence-backed static finding attached to the hypothesis.');
    const finding = state.accessFindings.find((item) => item.id === input.findingId);
    if (!finding) return err('HYPOTHESIS_INVALID', `Finding "${input.findingId}" is not part of this investigation.`);
    const supported = new Set(['missing_authentication', 'missing_authorization', 'idor_candidate', 'user_resource_access', 'inconsistent_authorization']);
    if (!supported.has(finding.candidateType)) return err('UNSUPPORTED_CANDIDATE_TYPE', `Finding candidateType "${finding.candidateType}" is not supported by Phase 6.`);
    if (state.investigation.execution.runtimeVerifications >= state.investigation.budget.maxRuntimeVerifications) return err('BUDGET_EXCEEDED', 'Maximum runtime verifications for this investigation has been reached.');
    const targetKey = operationKey(`${input.investigationId}|runtime|${input.hypothesisId}|${input.findingId}|${stableStringify({ target: input.target, sessions: input.sessions ?? [], sessionParams: input.sessionParams ?? {} })}`);
    if (state.investigation.execution.operations.includes(`runtime:${targetKey}`)) return err('DUPLICATE_OPERATION', 'This hypothesis and target have already been verified.');
    const elapsed = checkTime(state);
    if (elapsed) return err('BUDGET_EXCEEDED', elapsed);
    let result;
    try {
      result = await verifyFinding(config, input);
    } catch {
      state.investigation.status = 'failed';
      state.investigation.updatedAt = now();
      return err('INTERNAL_ERROR', 'Runtime verification failed unexpectedly.');
    }
    if (!result.ok) return err(result.error.code, result.error.message);
    state.investigation.execution.runtimeVerifications += 1;
    state.investigation.execution.operations.push(`runtime:${targetKey}`);
    state.runtimeResults.set(input.hypothesisId, result.data.result);
    const runtimeRef = addEvidence(state, { kind: 'runtime_verification', reference: `runtime:${input.hypothesisId}`, summary: result.data.result.summary });
    if (!hypothesis.evidenceRefs.includes(runtimeRef)) hypothesis.evidenceRefs.push(runtimeRef);
    state.investigation.runtimeResults[input.hypothesisId] = {
      status: result.data.result.status,
      confidence: result.data.result.confidence,
      summary: result.data.result.summary,
      requestsIssued: result.data.result.requestsIssued,
      blockedReason: result.data.result.blockedReason,
      evidenceRef: runtimeRef,
    };
    addStep(state, 'runtime_verification', result.data.result.summary, [runtimeRef]);
    hypothesis.status = result.data.result.status === 'verified' ? 'verified' : result.data.result.status === 'not_reproduced' ? 'not_reproduced' : result.data.result.status === 'blocked' ? 'blocked' : 'inconclusive';
    const investigationFinding = state.investigation.findings.find((item) => item.findingId === input.findingId);
    if (investigationFinding) {
      investigationFinding.lifecycle = result.data.result.status === 'verified' ? 'runtime_verified' : result.data.result.status === 'not_reproduced' ? 'not_reproduced' : result.data.result.status === 'inconclusive' ? 'inconclusive' : result.data.result.status === 'blocked' ? 'blocked' : 'investigated';
      investigationFinding.runtimeVerificationStatus = result.data.result.status;
    }
    const pendingVerification = state.investigation.hypotheses.some((item) => item.findingId !== null && item.status === 'open');
    state.investigation.status = pendingVerification ? 'awaiting_verification' : 'completed';
    state.investigation.updatedAt = now();
    return ok(state.investigation);
  });
}

const SECRET_KEY_RE = /authorization|cookie|set-cookie|api[_-]?key|token|password|secret|credential/i;
const SECRET_VALUE_RE = /Bearer\s+[A-Za-z0-9._-]+|sk-[A-Za-z0-9_-]+|ghp_[A-Za-z0-9]+/g;
function sanitize(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[TRUNCATED]';
  if (typeof value === 'string') return value.replace(SECRET_VALUE_RE, '[REDACTED]').slice(0, 2_000);
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => sanitize(item, depth + 1));
  if (value && typeof value === 'object') {
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) output[key] = SECRET_KEY_RE.test(key) ? '[REDACTED]' : sanitize(child, depth + 1);
    return output;
  }
  return value;
}

export function getInvestigation(investigationId: string): ToolOutcome<SecurityInvestigation> {
  const state = get(investigationId);
  if (!state) return err('INVESTIGATION_NOT_FOUND', `Investigation "${investigationId}" was not found.`);
  const safe = sanitize(state.investigation);
  return ok(JSON.parse(JSON.stringify(safe)) as SecurityInvestigation);
}

export const SECURITY_AGENT_INSTRUCTIONS = `CodeSentinel Phase 7 is a bounded security investigation toolkit for an external AI agent. Call start_security_investigation first with the configured project path, a narrow scope, and a concrete question. Call run_security_analysis once, then inspect its project, route, scanner, and access-control evidence identifiers. Call record_security_hypothesis only when the hypothesis cites at least one returned evidence reference; static findings are candidates, not proof. Call request_runtime_verification only for an existing evidence-backed Phase 5 access-control finding when an operator has explicitly authorized the exact runtime target and supplied any required test sessions. Call get_investigation to collect the bounded final state and evidence.

Runtime verification is optional. Never bypass path guards, target authorization, SSRF protection, session rules, request/redirect/timeout/response limits, or destructive-method controls. Do not repeat identical operations, do not discover credentials, do not send arbitrary HTTP, and stop when an investigation budget is exhausted. Report blocked, inconclusive, and uncertain outcomes as uncertainty; do not invent semantic proof or mark findings fixed. CodeSentinel does not contain an LLM API key or call a model; the external MCP client performs reasoning while CodeSentinel enforces filesystem boundaries, deterministic analysis, runtime safety, evidence collection, and redaction.`;

export function resetInvestigationsForTests(): void {
  investigations.clear();
  investigationLocks.clear();
}
