import crypto from 'node:crypto';
import type { AppConfig } from '../config.js';
import { getInvestigation, recordHypothesis, requestRuntimeVerification, runSecurityAnalysis, startInvestigation } from '../investigation/orchestrator.js';
import type { SecurityInvestigation } from '../investigation/types.js';
import { generateSecurityReport } from '../report/engine.js';
import { detachedRedacted, redactReportValue } from '../report/redaction.js';
import type { SecurityReport, SecurityReportFinding } from '../report/types.js';
import { err, ok, type ToolErrorCode, type ToolOutcome } from '../types.js';
import type { RecordAuditHypothesisInput, RuntimeVerificationRequestInput, StartSecurityAuditInput } from '../validation/schemas.js';
import { buildCapabilityPlan, FOCUS_FINDING_CATEGORIES, inferFocus, scopesFor } from './planner.js';
import type { AuditHypothesis, AuditLimits, AuditSession, AuditStateSummary, AuditStatus, AuditStep, AuditToolName, CapabilityPlan, FindingTrace } from './types.js';

export const AUDIT_OBJECTIVE_NOTICE = 'An objective describes what to review. It is not a finding and not a claim that a vulnerability exists.';
export const DEFAULT_LIMITS: AuditLimits = { maxSteps: 25, maxHypotheses: 10, maxEvidenceRefs: 100, maxVerificationRequests: 5, maxOutputBytes: 60_000, maxElapsedMs: 300_000 };
const FLOORS: AuditLimits = { maxSteps: 1, maxHypotheses: 1, maxEvidenceRefs: 1, maxVerificationRequests: 1, maxOutputBytes: 8_000, maxElapsedMs: 1_000 };
const CEILINGS: AuditLimits = { maxSteps: 100, maxHypotheses: 25, maxEvidenceRefs: 100, maxVerificationRequests: 10, maxOutputBytes: 200_000, maxElapsedMs: 600_000 };
const MAX_SESSIONS = 100;
const MAX_ERRORS = 50;
const MAX_BLOCKED = 50;
const LIST_CAP = 100;

const TRANSITIONS: Record<AuditStatus, readonly AuditStatus[]> = {
  created: ['planning', 'blocked', 'failed'],
  planning: ['investigating', 'blocked', 'failed'],
  investigating: ['awaiting_verification', 'completed', 'blocked', 'failed'],
  awaiting_verification: ['completed', 'blocked', 'failed'],
  completed: [],
  blocked: [],
  failed: [],
};

export function canTransition(from: AuditStatus, to: AuditStatus): boolean {
  return TRANSITIONS[from].includes(to);
}
const isTerminal = (status: AuditStatus): boolean => TRANSITIONS[status].length === 0;

const sessions = new Map<string, AuditSession>();
const locks = new Map<string, Promise<void>>();

export function resetAuditSessionsForTests(): void {
  sessions.clear();
  locks.clear();
}

const newId = (prefix: string): string => `${prefix}-${crypto.randomUUID()}`;
const now = (): string => new Date().toISOString();
const redactText = (value: string): string => String(redactReportValue(value));

async function withLock<T>(key: string, operation: () => Promise<T>): Promise<T> {
  const previous = locks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => { release = resolve; });
  locks.set(key, current);
  await previous;
  try {
    return await operation();
  } finally {
    release();
    if (locks.get(key) === current) locks.delete(key);
  }
}

function notFound<T>(investigationId: string): ToolOutcome<T> {
  return err('INVESTIGATION_NOT_FOUND', `Security audit "${investigationId}" was not found.`);
}

function resolveLimits(partial?: Partial<AuditLimits>): ToolOutcome<AuditLimits> {
  const merged: AuditLimits = { ...DEFAULT_LIMITS };
  for (const key of Object.keys(DEFAULT_LIMITS) as Array<keyof AuditLimits>) {
    const value = partial?.[key];
    if (value !== undefined) merged[key] = value;
    if (!Number.isInteger(merged[key]) || merged[key] < FLOORS[key] || merged[key] > CEILINGS[key]) {
      return err('INVALID_INPUT', `Limit "${key}" must be an integer between ${FLOORS[key]} and ${CEILINGS[key]}.`);
    }
  }
  return ok(merged);
}

function moveTo(session: AuditSession, to: AuditStatus, tool: AuditToolName): ToolOutcome<true> {
  if (session.status === to) return ok(true);
  if (!canTransition(session.status, to)) return err('INVALID_TRANSITION', `Audit cannot move from "${session.status}" to "${to}".`);
  session.status = to;
  session.currentStep = tool;
  session.updatedAt = now();
  return ok(true);
}

function pushError(session: AuditSession, message: string): void {
  if (session.errors.length < MAX_ERRORS) session.errors.push(redactText(message).slice(0, 500));
}

function pushBlocked(session: AuditSession, tool: AuditToolName, code: string, reason: string): void {
  if (session.blockedOperations.length < MAX_BLOCKED) {
    session.blockedOperations.push({ id: newId('blocked'), tool, code, reason: redactText(reason).slice(0, 500), at: now() });
  }
  session.updatedAt = now();
}

function refuse<T>(session: AuditSession, tool: AuditToolName, code: ToolErrorCode, reason: string, terminal?: 'blocked'): ToolOutcome<T> {
  pushBlocked(session, tool, code, reason);
  if (terminal && !isTerminal(session.status)) moveTo(session, terminal, tool);
  return err<T>(code, reason);
}

/** Time and step bounds. Applied before every state-changing operation. */
function preflight(session: AuditSession, tool: AuditToolName): ToolOutcome<true> {
  if (Date.now() - Date.parse(session.createdAt) > session.limits.maxElapsedMs) {
    return refuse(session, tool, 'BUDGET_EXCEEDED', 'Audit elapsed-time limit exceeded.', 'blocked');
  }
  if (session.steps.length >= session.limits.maxSteps) {
    return refuse(session, tool, 'BUDGET_EXCEEDED', 'Maximum audit steps reached.', 'blocked');
  }
  return ok(true);
}

function addStep(
  session: AuditSession,
  tool: AuditToolName,
  status: AuditStep['status'],
  summary: string,
  startedAt: string,
  extra: Partial<Pick<AuditStep, 'investigationStepIds' | 'evidenceCount' | 'objectIds'>> = {}
): AuditStep {
  const finishedAt = now();
  const step: AuditStep = {
    id: newId('audit-step'),
    sequence: session.steps.length + 1,
    tool,
    status,
    startedAt,
    finishedAt,
    summary: redactText(summary).slice(0, 500),
    investigationStepIds: extra.investigationStepIds ?? [],
    evidenceCount: extra.evidenceCount ?? 0,
    objectIds: extra.objectIds ?? [],
  };
  session.steps.push(step);
  session.currentStep = tool;
  session.updatedAt = finishedAt;
  return step;
}

function syncTerminal(session: AuditSession, underlying: SecurityInvestigation['status'], tool: AuditToolName): void {
  if (underlying === 'failed') moveTo(session, 'failed', tool);
  else if (underlying === 'blocked') moveTo(session, 'blocked', tool);
}

function remainingWork(session: AuditSession, inv: SecurityInvestigation, analysisDone: boolean): string[] {
  if (session.status === 'completed') return [];
  if (session.status === 'blocked' || session.status === 'failed') return [`Audit is ${session.status}; no further audit work is possible.`];
  const work: string[] = [];
  if (session.status === 'created') work.push('Call plan_security_investigation.');
  if (!analysisDone) {
    work.push('Call run_audit_analysis (project discovery, static scan, route discovery, access-control analysis).');
    return work;
  }
  if (inv.status === 'awaiting_verification') {
    const candidates = inv.findings.filter((f) => f.origin === 'access_control').length;
    work.push(`Verify at least one access-control finding (${candidates} candidate(s)): record_audit_hypothesis with a findingId, then request_audit_verification against an operator-authorized local target.`);
  }
  if (inv.status === 'completed') work.push('Call complete_security_audit.');
  else if (inv.status === 'blocked' || inv.status === 'failed') work.push(`The underlying investigation is ${inv.status}.`);
  return work;
}

function boundSize(summary: AuditStateSummary): AuditStateSummary {
  const s = summary;
  const size = (): number => Buffer.byteLength(JSON.stringify(s, null, 2), 'utf8');
  const max = s.limits.maxOutputBytes;
  const shrinkers: Array<() => void> = [
    () => { s.evidenceRefs.listed.length = Math.min(s.evidenceRefs.listed.length, 25); },
    () => { s.findings.length = Math.min(s.findings.length, 25); },
    () => { s.steps.length = Math.min(s.steps.length, 10); },
    () => { s.evidenceRefs.listed.length = 0; },
    () => { s.findings.length = Math.min(s.findings.length, 5); s.verificationResults.length = Math.min(s.verificationResults.length, 5); },
    () => { s.steps.length = 0; s.hypotheses.length = Math.min(s.hypotheses.length, 5); s.blockedOperations.length = Math.min(s.blockedOperations.length, 5); },
    () => { s.findings.length = 0; s.verificationResults.length = 0; s.hypotheses.length = 0; s.errors.length = Math.min(s.errors.length, 3); },
    () => { for (const capability of s.availableCapabilities) capability.purpose = ''; },
  ];
  for (const shrink of shrinkers) {
    if (size() <= max) break;
    shrink();
    s.outputTruncated = true;
  }
  s.evidenceRefs.truncated = s.evidenceRefs.listed.length < s.evidenceRefs.total;
  return s;
}

function buildState(session: AuditSession): ToolOutcome<AuditStateSummary> {
  const snapshot = getInvestigation(session.investigationId);
  if (!snapshot.ok) return err('INVESTIGATION_NOT_FOUND', 'The underlying investigation record is no longer available.');
  const inv = snapshot.data;
  const analysisDone = session.completedCapabilities.includes('run_audit_analysis');
  const remaining = remainingWork(session, inv, analysisDone);
  const phase7Status = new Map(inv.hypotheses.map((h) => [h.id, h.status] as const));
  const byPhase7 = new Map(session.hypotheses.filter((h) => h.investigationHypothesisId !== null).map((h) => [h.investigationHypothesisId as string, h] as const));

  const hypotheses: AuditHypothesis[] = session.hypotheses.map((h) => {
    const underlying = h.investigationHypothesisId ? phase7Status.get(h.investigationHypothesisId) : undefined;
    return { ...h, evidenceRefs: [...h.evidenceRefs], status: underlying ? (underlying === 'open' ? 'linked' : underlying) : h.status };
  });

  const summary: AuditStateSummary = {
    investigationId: session.investigationId,
    objective: { ...session.objective, scopes: [...session.objective.scopes] },
    status: session.status,
    currentStep: session.currentStep,
    complete: session.status === 'completed',
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    limits: { ...session.limits },
    usage: { steps: session.steps.length, hypotheses: session.hypotheses.length, verificationRequests: session.verificationAttempts },
    totals: {
      steps: session.steps.length,
      hypotheses: session.hypotheses.length,
      findings: inv.findings.length,
      evidenceRefs: inv.evidence.length,
      verificationResults: Object.keys(inv.runtimeResults).length,
      blockedOperations: session.blockedOperations.length,
    },
    availableCapabilities: buildCapabilityPlan(session),
    completedCapabilities: [...session.completedCapabilities],
    remainingWork: remaining,
    steps: session.steps.map((s) => ({ ...s, investigationStepIds: [...s.investigationStepIds], objectIds: [...s.objectIds] })),
    hypotheses,
    evidenceRefs: {
      total: inv.evidence.length,
      truncated: inv.evidence.length > session.limits.maxEvidenceRefs,
      listed: inv.evidence.slice(0, session.limits.maxEvidenceRefs).map((e) => ({ id: e.id, kind: e.kind, reference: e.reference, summary: e.summary })),
    },
    findings: inv.findings.slice(0, LIST_CAP).map((f) => ({
      findingId: f.findingId, origin: f.origin, title: f.title, category: f.category, candidateType: f.candidateType,
      severity: f.severity, confidence: f.confidence, lifecycle: f.lifecycle, runtimeVerificationStatus: f.runtimeVerificationStatus, path: f.path, file: f.file,
    })),
    verificationResults: Object.entries(inv.runtimeResults).map(([phase7Id, r]) => ({
      auditHypothesisId: byPhase7.get(phase7Id)?.id ?? '',
      investigationHypothesisId: phase7Id,
      status: r.status, confidence: r.confidence, summary: r.summary, requestsIssued: r.requestsIssued, blockedReason: r.blockedReason, evidenceRef: r.evidenceRef,
    })),
    blockedOperations: session.blockedOperations.map((b) => ({ ...b })),
    errors: session.errors.slice(0, 10),
    outputTruncated: false,
  };
  return ok(boundSize(detachedRedacted(summary)));
}

export function startSecurityAudit(config: AppConfig, input: StartSecurityAuditInput): ToolOutcome<AuditStateSummary> {
  const text = redactText(input.objective.trim());
  if (text.length === 0) return err('INVALID_INPUT', 'A security objective is required.');
  const focus = input.focus ?? inferFocus(text);
  const target = input.target ? redactText(input.target.trim()) : null;
  if ((focus === 'route' || focus === 'finding') && !target) return err('INVALID_INPUT', `A target is required for focus "${focus}".`);
  if (target && focus !== 'route' && focus !== 'finding') return err('INVALID_INPUT', 'A target is only valid with focus "route" or "finding".');
  const limits = resolveLimits(input.limits);
  if (!limits.ok) return limits;

  if (sessions.size >= MAX_SESSIONS) {
    const oldest = [...sessions.values()].filter((s) => isTerminal(s.status)).sort((a, b) => a.updatedAt.localeCompare(b.updatedAt))[0];
    if (!oldest) return err('BUDGET_EXCEEDED', 'The bounded audit store is full; finish an existing audit first.');
    sessions.delete(oldest.investigationId);
    locks.delete(oldest.investigationId);
  }

  const scopes = scopesFor(focus);
  const started = startInvestigation(config, {
    projectPath: config.projectRoot,
    scope: scopes,
    hypothesis: `Security objective (not a finding): ${text}`.slice(0, 2_000),
    budget: { maxHypotheses: limits.data.maxHypotheses, maxRuntimeVerifications: limits.data.maxVerificationRequests, maxElapsedMs: limits.data.maxElapsedMs },
  });
  if (!started.ok) return err(started.error.code, started.error.message);

  const timestamp = now();
  const session: AuditSession = {
    investigationId: started.data.id,
    objective: { text, focus, target, scopes, notice: AUDIT_OBJECTIVE_NOTICE },
    status: 'created',
    currentStep: 'start_security_audit',
    createdAt: timestamp,
    updatedAt: timestamp,
    limits: limits.data,
    hypotheses: [],
    steps: [],
    blockedOperations: [],
    errors: [],
    completedCapabilities: ['start_security_audit'],
    verificationAttempts: 0,
  };
  sessions.set(session.investigationId, session);
  return buildState(session);
}

export function getSecurityAuditState(investigationId: string): ToolOutcome<AuditStateSummary> {
  const session = sessions.get(investigationId);
  return session ? buildState(session) : notFound(investigationId);
}

function makePlan(session: AuditSession): CapabilityPlan {
  return {
    investigationId: session.investigationId,
    status: session.status,
    objective: { ...session.objective, scopes: [...session.objective.scopes] },
    relevantFindingCategories: [...FOCUS_FINDING_CATEGORIES[session.objective.focus]],
    capabilities: buildCapabilityPlan(session),
    notice: 'This is a capability plan, not a security conclusion. It does not assert that any vulnerability exists. The external agent chooses which capability to invoke.',
  };
}

export function planSecurityInvestigation(investigationId: string): ToolOutcome<CapabilityPlan> {
  const session = sessions.get(investigationId);
  if (!session) return notFound(investigationId);
  if (session.status === 'created') {
    const pre = preflight(session, 'plan_security_investigation');
    if (!pre.ok) return pre;
    const startedAt = now();
    moveTo(session, 'planning', 'plan_security_investigation');
    addStep(session, 'plan_security_investigation', 'completed', 'Deterministic capability plan produced.', startedAt);
    session.completedCapabilities.push('plan_security_investigation');
  }
  return ok(makePlan(session));
}

export async function runAuditAnalysis(config: AppConfig, investigationId: string): Promise<ToolOutcome<AuditStateSummary>> {
  return withLock(investigationId, async () => {
    const session = sessions.get(investigationId);
    if (!session) return notFound<AuditStateSummary>(investigationId);
    if (session.completedCapabilities.includes('run_audit_analysis')) return buildState(session);
    if (session.status !== 'planning') {
      return err('INVALID_TRANSITION', session.status === 'created' ? 'Call plan_security_investigation before running analysis.' : `Analysis cannot start from audit status "${session.status}".`);
    }
    const pre = preflight(session, 'run_audit_analysis');
    if (!pre.ok) return pre;
    const startedAt = now();
    moveTo(session, 'investigating', 'run_audit_analysis');
    const result = await runSecurityAnalysis(config, investigationId);
    if (!result.ok) {
      const blocked = result.error.code === 'BUDGET_EXCEEDED';
      addStep(session, 'run_audit_analysis', blocked ? 'blocked' : 'failed', result.error.message, startedAt);
      pushError(session, `${result.error.code}: ${result.error.message}`);
      if (blocked) pushBlocked(session, 'run_audit_analysis', result.error.code, result.error.message);
      moveTo(session, blocked ? 'blocked' : 'failed', 'run_audit_analysis');
      return err(result.error.code, result.error.message);
    }
    const snapshot = getInvestigation(investigationId);
    if (!snapshot.ok) return err('INVESTIGATION_NOT_FOUND', 'The underlying investigation record is no longer available.');
    addStep(session, 'run_audit_analysis', 'completed', `Deterministic analysis finished: ${snapshot.data.findings.length} candidate finding(s), ${snapshot.data.evidence.length} evidence item(s).`, startedAt, {
      investigationStepIds: snapshot.data.steps.map((s) => s.id),
      evidenceCount: snapshot.data.evidence.length,
    });
    session.completedCapabilities.push('run_audit_analysis');
    if (snapshot.data.status === 'awaiting_verification') moveTo(session, 'awaiting_verification', 'run_audit_analysis');
    return buildState(session);
  });
}

const contentKey = (h: { category: string; affectedLocation: string; description: string }): string =>
  [h.category, h.affectedLocation, h.description].map((v) => v.trim().toLowerCase().replace(/\s+/g, ' ')).join('|');

export function recordAuditHypothesis(input: RecordAuditHypothesisInput): ToolOutcome<AuditHypothesis> {
  const session = sessions.get(input.investigationId);
  if (!session) return notFound(input.investigationId);
  if (!(session.status === 'planning' || session.status === 'investigating' || session.status === 'awaiting_verification')) {
    return err('INVALID_TRANSITION', session.status === 'created' ? 'Call plan_security_investigation before recording hypotheses.' : `A hypothesis cannot be recorded while the audit is "${session.status}".`);
  }
  const pre = preflight(session, 'record_audit_hypothesis');
  if (!pre.ok) return pre;
  const candidate = { category: redactText(input.category), affectedLocation: redactText(input.affectedLocation), description: redactText(input.description) };
  if (session.hypotheses.some((h) => h.id === input.hypothesisId)) return err('DUPLICATE_OPERATION', `Hypothesis "${input.hypothesisId}" already exists in this audit.`);
  if (session.hypotheses.some((h) => contentKey(h) === contentKey(candidate))) return err('DUPLICATE_OPERATION', 'An identical hypothesis has already been recorded.');
  if (session.hypotheses.length >= session.limits.maxHypotheses) return refuse(session, 'record_audit_hypothesis', 'BUDGET_EXCEEDED', 'Maximum hypotheses for this audit has been reached.');

  if (input.findingId && session.completedCapabilities.includes('run_audit_analysis')) {
    const snapshot = getInvestigation(session.investigationId);
    if (!snapshot.ok) return err('INVESTIGATION_NOT_FOUND', 'The underlying investigation record is no longer available.');
    if (!snapshot.data.findings.some((f) => f.findingId === input.findingId && f.origin === 'access_control')) {
      return err('HYPOTHESIS_INVALID', `Finding "${input.findingId}" is not an access-control finding in this investigation.`);
    }
  }

  const startedAt = now();
  const hypothesis: AuditHypothesis = {
    kind: 'hypothesis',
    isEvidence: false,
    id: input.hypothesisId,
    category: candidate.category,
    description: candidate.description,
    affectedLocation: candidate.affectedLocation,
    reason: redactText(input.reason),
    findingId: input.findingId ?? null,
    investigationHypothesisId: null,
    evidenceRefs: [],
    status: 'proposed',
    createdAt: startedAt,
  };
  session.hypotheses.push(hypothesis);
  addStep(session, 'record_audit_hypothesis', 'completed', `Hypothesis ${hypothesis.id} recorded (unverified, not evidence).`, startedAt, { objectIds: [hypothesis.id] });
  return ok(JSON.parse(JSON.stringify(hypothesis)) as AuditHypothesis);
}

export async function requestAuditVerification(config: AppConfig, input: RuntimeVerificationRequestInput): Promise<ToolOutcome<AuditStateSummary>> {
  return withLock(input.investigationId, async () => {
    const session = sessions.get(input.investigationId);
    if (!session) return notFound<AuditStateSummary>(input.investigationId);
    if (session.status !== 'awaiting_verification') return err('INVALID_TRANSITION', `Runtime verification cannot start while the audit is "${session.status}".`);
    const pre = preflight(session, 'request_audit_verification');
    if (!pre.ok) return pre;
    const hypothesis = session.hypotheses.find((h) => h.id === input.hypothesisId);
    if (!hypothesis) return err('HYPOTHESIS_NOT_FOUND', `Hypothesis "${input.hypothesisId}" was not found in this audit.`);
    if (hypothesis.findingId && hypothesis.findingId !== input.findingId) return err('HYPOTHESIS_INVALID', 'The finding must match the finding recorded on the hypothesis.');
    if (session.verificationAttempts >= session.limits.maxVerificationRequests) {
      return refuse(session, 'request_audit_verification', 'BUDGET_EXCEEDED', 'Maximum runtime verification requests for this audit reached.');
    }
    session.verificationAttempts += 1; // rejected attempts count too: no unbounded retry loop
    const startedAt = now();
    const known = new Set(session.steps.flatMap((s) => s.investigationStepIds));
    const fail = (code: ToolErrorCode, message: string): ToolOutcome<AuditStateSummary> => {
      addStep(session, 'request_audit_verification', 'blocked', `${code}: ${message}`, startedAt, { objectIds: [hypothesis.id, input.findingId] });
      pushBlocked(session, 'request_audit_verification', code, message);
      const current = getInvestigation(session.investigationId);
      if (current.ok) syncTerminal(session, current.data.status, 'request_audit_verification');
      return err(code, message);
    };

    let phase7Id = hypothesis.investigationHypothesisId;
    if (!phase7Id) {
      const promoted = await recordHypothesis(config, {
        investigationId: input.investigationId,
        title: `${hypothesis.category}: ${hypothesis.affectedLocation}`.slice(0, 256),
        description: `${hypothesis.description} Reason: ${hypothesis.reason}`.slice(0, 4_000),
        findingId: input.findingId,
        evidenceRefs: [`accessFinding:${input.findingId}`],
      });
      if (!promoted.ok) return fail(promoted.error.code, promoted.error.message);
      phase7Id = promoted.data.id;
      hypothesis.investigationHypothesisId = phase7Id;
      hypothesis.findingId = input.findingId;
      hypothesis.status = 'linked';
    }

    const result = await requestRuntimeVerification(config, { ...input, hypothesisId: phase7Id });
    if (!result.ok) return fail(result.error.code, result.error.message);

    const snapshot = getInvestigation(session.investigationId);
    if (!snapshot.ok) return err('INVESTIGATION_NOT_FOUND', 'The underlying investigation record is no longer available.');
    const inv = snapshot.data;
    const linked = inv.hypotheses.find((h) => h.id === phase7Id);
    if (linked) {
      hypothesis.status = linked.status === 'open' ? 'linked' : linked.status;
      hypothesis.evidenceRefs = linked.evidenceRefs.slice(0, 20);
    }
    const runtime = inv.runtimeResults[phase7Id];
    addStep(session, 'request_audit_verification', runtime?.status === 'blocked' ? 'blocked' : 'completed', runtime?.summary ?? 'Runtime verification finished.', startedAt, {
      investigationStepIds: inv.steps.filter((s) => !known.has(s.id)).map((s) => s.id),
      evidenceCount: runtime ? 1 : 0,
      objectIds: [hypothesis.id, input.findingId],
    });
    if (runtime?.status === 'blocked') pushBlocked(session, 'request_audit_verification', 'TARGET_BLOCKED', runtime.blockedReason ?? 'Runtime verification was blocked by existing safety controls.');
    syncTerminal(session, inv.status, 'request_audit_verification');
    return buildState(session);
  });
}

export function completeSecurityAudit(investigationId: string): ToolOutcome<AuditStateSummary> {
  const session = sessions.get(investigationId);
  if (!session) return notFound(investigationId);
  if (session.status === 'completed') return buildState(session);
  if (isTerminal(session.status)) return err('INVALID_TRANSITION', `A ${session.status} audit cannot be completed.`);
  const snapshot = getInvestigation(session.investigationId);
  if (!snapshot.ok) return err('INVESTIGATION_NOT_FOUND', 'The underlying investigation record is no longer available.');
  const analysisDone = session.completedCapabilities.includes('run_audit_analysis');
  if (!analysisDone || snapshot.data.status !== 'completed') {
    return err('INVESTIGATION_INCOMPLETE', `Audit is incomplete. ${remainingWork(session, snapshot.data, analysisDone).join(' ')}`.trim());
  }
  const pre = preflight(session, 'complete_security_audit');
  if (!pre.ok) return pre;
  const startedAt = now();
  moveTo(session, 'completed', 'complete_security_audit');
  addStep(session, 'complete_security_audit', 'completed', 'All required deterministic work finished; audit marked complete.', startedAt);
  session.completedCapabilities.push('complete_security_audit');
  return buildState(session);
}

function traceFinding(session: AuditSession, inv: SecurityInvestigation, finding: SecurityReportFinding): FindingTrace {
  const wanted = new Set([...finding.evidenceRefs, ...finding.sourceRefs]);
  const evidence = inv.evidence.filter((e) => wanted.has(e.id) || wanted.has(e.reference));
  const keys = new Set(evidence.flatMap((e) => [e.id, e.reference]));
  const investigationSteps = inv.steps.filter((s) => s.evidenceRefs.some((r) => keys.has(r)));
  const stepIds = new Set(investigationSteps.map((s) => s.id));
  const auditSteps = session.steps.filter((a) => a.investigationStepIds.some((id) => stepIds.has(id)));
  const auditHypothesis = session.hypotheses.find((h) => h.investigationHypothesisId !== null && h.investigationHypothesisId === finding.hypothesisId);
  return {
    findingId: finding.findingId,
    auditHypothesisId: auditHypothesis?.id ?? null,
    investigationHypothesisId: finding.hypothesisId,
    evidence: evidence.slice(0, 20).map((e) => ({ id: e.id, kind: e.kind, reference: e.reference })),
    investigationStepIds: [...stepIds],
    auditStepIds: auditSteps.map((a) => a.id),
    traceable: evidence.length > 0 && auditSteps.length > 0,
  };
}

export function generateSecurityAuditReport(investigationId: string): ToolOutcome<{ report: SecurityReport; traceability: FindingTrace[] }> {
  const session = sessions.get(investigationId);
  if (!session) return notFound(investigationId);
  const snapshot = getInvestigation(session.investigationId);
  if (!snapshot.ok) return err('INVESTIGATION_NOT_FOUND', 'The underlying investigation record is no longer available.');
  if (session.status !== 'completed') {
    return err('INVESTIGATION_INCOMPLETE', `A report requires a completed audit. ${remainingWork(session, snapshot.data, session.completedCapabilities.includes('run_audit_analysis')).join(' ')}`.trim());
  }
  const report = generateSecurityReport(session.investigationId);
  if (!report.ok) return err(report.error.code, report.error.message);
  if (!session.completedCapabilities.includes('generate_security_audit_report')) session.completedCapabilities.push('generate_security_audit_report');
  return ok({ report: report.data, traceability: detachedRedacted(report.data.findings.map((f) => traceFinding(session, snapshot.data, f))) });
}
