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

function boundary(config: AppConfig, projectPath: string): string | null {
  const requested = path.resolve(projectPath);
  const configured = path.resolve(config.projectRoot);
  return requested === configured ? null : `Project path must equal the configured project root; access to "${projectPath}" is outside the authorized investigation boundary.`;
}

function get(idValue: string): InvestigationInternals | null {
  return investigations.get(idValue) ?? null;
}

function operationKey(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, ' ');
}

function checkTime(state: InvestigationInternals): string | null {
  if (Date.now() - Date.parse(state.investigation.createdAt) > state.investigation.budget.maxElapsedMs) {
    state.investigation.status = 'blocked';
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
  return { findingId: finding.id, title: finding.title, severity: finding.severity, confidence: finding.confidence, lifecycle: 'static_candidate', runtimeVerificationStatus: finding.verificationStatus };
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
  const investigation: SecurityInvestigation = {
    id: id('investigation'), projectPath: path.resolve(input.projectPath), scope: input.scope,
    status: 'created', hypothesis: input.hypothesis, steps: [], evidence: [], hypotheses: [], findings: [], analysis: null,
    budget, execution: { analysisSteps: 0, runtimeVerifications: 0, evidenceBytes: 0, operations: [] }, createdAt: timestamp, updatedAt: timestamp,
  };
  investigations.set(investigation.id, { investigation, accessFindings: [], routes: [], securityFindings: [], runtimeResults: new Map() });
  return ok(investigation);
}

export async function runSecurityAnalysis(config: AppConfig, investigationId: string): Promise<ToolOutcome<SecurityInvestigation>> {
  const state = get(investigationId);
  if (!state) return err('INVESTIGATION_NOT_FOUND', `Investigation "${investigationId}" was not found.`);
  const duplicate = state.investigation.execution.operations.includes('static-analysis');
  if (duplicate) return err('DUPLICATE_OPERATION', 'Static analysis has already been run for this investigation.');
  if (state.investigation.status !== 'created') return err('INVALID_TRANSITION', `Static analysis cannot start from status "${state.investigation.status}".`);
  const elapsed = checkTime(state);
  if (elapsed) return err('BUDGET_EXCEEDED', elapsed);
  state.investigation.status = 'running';
  state.investigation.execution.operations.push('static-analysis');
  try {
    const profile = runProjectDiscovery(config.projectRoot);
    const scan = await scanProject(config);
    const routes = discoverRoutes(config);
    if (!routes.ok) throw new Error(routes.error.message);
    const access = analyzeAccessControl(config, routes.data.entries);
    if (state.investigation.budget.maxAnalysisSteps < 4) throw new Error('Analysis-step budget is too small for the required deterministic pipeline.');
    state.investigation.execution.analysisSteps = 4;
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
    state.investigation.status = 'awaiting_verification';
    state.investigation.updatedAt = now();
    return ok(state.investigation);
  } catch (e) {
    state.investigation.status = 'failed';
    state.investigation.updatedAt = now();
    return err('ANALYSIS_FAILED', 'Deterministic security analysis failed unexpectedly.');
  }
}

export function recordHypothesis(config: AppConfig, input: { investigationId: string; title: string; description: string; findingId?: string; evidenceRefs: string[]; severity?: SecurityHypothesis['severity']; confidence?: SecurityHypothesis['confidence'] }): ToolOutcome<SecurityHypothesis> {
  const state = get(input.investigationId);
  if (!state) return err('INVESTIGATION_NOT_FOUND', `Investigation "${input.investigationId}" was not found.`);
  if (state.investigation.status !== 'awaiting_verification') return err('INVALID_TRANSITION', `A hypothesis cannot be recorded from status "${state.investigation.status}".`);
  if (state.investigation.hypotheses.length >= state.investigation.budget.maxHypotheses) return err('BUDGET_EXCEEDED', 'Maximum hypotheses for this investigation has been reached.');
  const key = operationKey(`${input.title}|${input.findingId ?? ''}|${[...input.evidenceRefs].sort().join('|')}`);
  if (state.investigation.execution.operations.includes(`hypothesis:${key}`)) return err('DUPLICATE_OPERATION', 'An identical hypothesis has already been recorded.');
  if (input.evidenceRefs.length === 0) return err('HYPOTHESIS_INVALID', 'A hypothesis must contain at least one evidence reference.');
  const available = new Set(state.investigation.evidence.map((e) => e.reference));
  const missing = input.evidenceRefs.filter((ref) => !available.has(ref));
  if (missing.length > 0) return err('HYPOTHESIS_INVALID', `Evidence references are not available: ${missing.join(', ')}.`);
  if (input.findingId && !state.accessFindings.some((finding) => finding.id === input.findingId)) return err('HYPOTHESIS_INVALID', `Finding "${input.findingId}" is not part of this investigation.`);
  const hypothesis: SecurityHypothesis = { id: id('hypothesis'), title: input.title, description: input.description, findingId: input.findingId ?? null, evidenceRefs: input.evidenceRefs, severity: input.severity ?? null, confidence: input.confidence ?? null, status: 'open', createdAt: now() };
  state.investigation.hypotheses.push(hypothesis);
  state.investigation.execution.operations.push(`hypothesis:${key}`);
  addStep(state, 'hypothesis', hypothesis.title, input.evidenceRefs);
  state.investigation.updatedAt = now();
  return ok(hypothesis);
}

export async function requestRuntimeVerification(config: AppConfig, input: VerifyFindingRequest & { investigationId: string; hypothesisId: string }): Promise<ToolOutcome<SecurityInvestigation>> {
  const state = get(input.investigationId);
  if (!state) return err('INVESTIGATION_NOT_FOUND', `Investigation "${input.investigationId}" was not found.`);
  if (state.investigation.status !== 'awaiting_verification') return err('INVALID_TRANSITION', `Runtime verification cannot start from status "${state.investigation.status}".`);
  const hypothesis = state.investigation.hypotheses.find((item) => item.id === input.hypothesisId);
  if (!hypothesis) return err('HYPOTHESIS_NOT_FOUND', `Hypothesis "${input.hypothesisId}" was not found in this investigation.`);
  if (!hypothesis.findingId || hypothesis.findingId !== input.findingId) return err('HYPOTHESIS_INVALID', 'Runtime verification must reference the static finding attached to the hypothesis.');
  if (state.investigation.execution.runtimeVerifications >= state.investigation.budget.maxRuntimeVerifications) return err('BUDGET_EXCEEDED', 'Maximum runtime verifications for this investigation has been reached.');
  const targetKey = operationKey(`${input.hypothesisId}|${input.findingId}|${input.target.allowedOrigin}`);
  if (state.investigation.execution.operations.includes(`runtime:${targetKey}`)) return err('DUPLICATE_OPERATION', 'This hypothesis and target have already been verified.');
  const elapsed = checkTime(state);
  if (elapsed) return err('BUDGET_EXCEEDED', elapsed);
  const result = await verifyFinding(config, input);
  if (!result.ok) return err(result.error.code, result.error.message);
  state.investigation.execution.runtimeVerifications += 1;
  state.investigation.execution.operations.push(`runtime:${targetKey}`);
  state.runtimeResults.set(input.hypothesisId, result.data.result);
  const runtimeRef = addEvidence(state, { kind: 'runtime_verification', reference: `runtime:${input.hypothesisId}`, summary: result.data.result.summary });
  addStep(state, 'runtime_verification', result.data.result.summary, [runtimeRef]);
  hypothesis.status = result.data.result.status === 'verified' ? 'verified' : result.data.result.status === 'not_reproduced' ? 'not_reproduced' : result.data.result.status === 'blocked' ? 'blocked' : 'inconclusive';
  const finding = state.investigation.findings.find((item) => item.findingId === input.findingId);
  if (finding) {
    finding.lifecycle = result.data.result.status === 'verified' ? 'runtime_verified' : result.data.result.status === 'not_reproduced' ? 'not_reproduced' : result.data.result.status === 'inconclusive' ? 'inconclusive' : 'investigated';
    finding.runtimeVerificationStatus = result.data.result.status;
  }
  state.investigation.status = 'completed';
  state.investigation.updatedAt = now();
  return ok(state.investigation);
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
  return ok(sanitize(state.investigation) as SecurityInvestigation);
}

export const SECURITY_AGENT_INSTRUCTIONS = `CodeSentinel Phase 7 is a bounded security investigation toolkit for an external AI agent. Discover the project, inspect its structure, run deterministic static scanning, discover routes, analyze access control, record evidence-backed hypotheses, and request runtime verification only for a justified existing finding and explicitly authorized target. Never assume unrestricted penetration testing, never bypass path or target guards, never request credentials automatically, and avoid repeated operations. CodeSentinel does not contain an LLM API key or call a model; the external MCP client performs reasoning while CodeSentinel enforces filesystem boundaries, static analysis, runtime target safety, request limits, evidence collection, and redaction. Produce final reports from the returned evidence and keep static suspected status separate from runtime outcomes.`;

export function resetInvestigationsForTests(): void {
  investigations.clear();
}
