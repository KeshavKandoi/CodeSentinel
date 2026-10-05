import { resolveProjectRoot } from '../config.js';
import type { AppConfig } from '../config.js';
import { err, ok, type ToolOutcome } from '../types.js';
import { scanProject } from '../security/scanner.js';
import { discoverRoutes } from '../routes/engine.js';
import { analyzeAccessControl } from '../access/engine.js';
import { runSecurityAuditPipeline } from '../audit/pipeline.js';
import { classifyRuntimeSetupFailure, type EnvironmentBlocker } from '../audit/environment.js';
import type { RuntimeTarget, TestSession } from '../runtime/types.js';
import { baselineFinding, listControlledRemediationRecords, type ControlledBaselineFinding, type ControlledRemediationRecord } from './engine.js';
import { retestFinding, type RetestFindingReceipt } from './retest.js';

export interface SecurityRemediationSweepInput {
  findingIds?: string[];
  remediationIds?: string[];
  target?: RuntimeTarget;
  sessions?: TestSession[];
  sessionParams?: Record<string, string>;
  runtimeSetupFailure?: { command: string; output: string };
}
export type SweepFinalState = 'resolved' | 'still_vulnerable' | 'inconclusive' | 'unsupported' | 'blocked';
export interface SweepFinding {
  findingId: string;
  remediationId: string;
  state: SweepFinalState;
  priorRetest: string | null;
  evidence: {
    originalFindingId: string | null;
    ruleId: string | null;
    originalEvidenceHash: string | null;
    validatedContentHash: string;
    validationStatus: 'passed';
    retest: RetestFindingReceipt | null;
    postScanFindingIds: string[];
  };
  limitation: string | null;
}
export interface SecurityRemediationSweepResult {
  projectRoot: string;
  securityStatus: 'secure' | 'inconclusive' | 'vulnerable';
  executionStatus: 'completed' | 'blocked' | 'not_required';
  verification: { attempted: boolean; completed: boolean; blocked: boolean; verifiedVulnerabilities: number; resolvedFindings: number; remainingFindings: number; inconclusiveFindings: number; unsupportedFindings: number };
  findings: { resolved: SweepFinding[]; stillVulnerable: SweepFinding[]; inconclusive: SweepFinding[]; unsupported: SweepFinding[]; blocked: SweepFinding[] };
  newFindings: ControlledBaselineFinding[];
  uncertainFindings: ControlledBaselineFinding[];
  baseline: { findingCount: number; complete: boolean; remediationCount: number; pendingRetest: number; alreadyRetested: number };
  postSweep: { findingCount: number; complete: boolean; auditReadOnly: boolean | null; unsupportedDomains: string[] };
  blockers: EnvironmentBlocker[];
  nextStep: { action: string; safeToRerun: true } | null;
  limitations: string[];
}

function sameCondition(a: ControlledBaselineFinding, b: ControlledBaselineFinding): boolean {
  return a.origin === b.origin && a.ruleId === b.ruleId && a.category === b.category && a.file === b.file && a.candidateType === b.candidateType && a.route === b.route && (a.id === b.id || a.evidenceHash === b.evidenceHash);
}

function possibleCondition(a: ControlledBaselineFinding, b: ControlledBaselineFinding): boolean {
  return a.origin === b.origin && a.ruleId === b.ruleId && a.category === b.category && a.file === b.file && a.candidateType === b.candidateType && a.route === b.route;
}

function originalSnapshot(record: ControlledRemediationRecord): ControlledBaselineFinding | null {
  return record.baselineFindings.find((finding) => finding.id === record.before.sourceId && finding.origin === record.before.origin) ?? null;
}

function correlatePostFindings(baseline: ControlledBaselineFinding[], current: ControlledBaselineFinding[]): { newFindings: ControlledBaselineFinding[]; uncertainFindings: ControlledBaselineFinding[] } {
  const matchedBefore = new Set<number>();
  const unmatched: ControlledBaselineFinding[] = [];
  for (const finding of current) {
    const index = baseline.findIndex((before, position) => !matchedBefore.has(position) && sameCondition(before, finding));
    if (index >= 0) matchedBefore.add(index);
    else unmatched.push(finding);
  }
  const uncertainFindings: ControlledBaselineFinding[] = [];
  const newFindings: ControlledBaselineFinding[] = [];
  for (const finding of unmatched) {
    if (baseline.some((before, position) => !matchedBefore.has(position) && possibleCondition(before, finding))) uncertainFindings.push(finding);
    else newFindings.push(finding);
  }
  return { newFindings, uncertainFindings };
}

export async function securityRemediationSweep(config: AppConfig, input: SecurityRemediationSweepInput = {}): Promise<ToolOutcome<SecurityRemediationSweepResult>> {
  try { if (!config.projectRoot || resolveProjectRoot(config.projectRoot) !== config.projectRoot) throw new Error('noncanonical'); }
  catch { return err('PATH_OUTSIDE_ROOT', 'The sweep requires a valid canonical project root.'); }
  const all = listControlledRemediationRecords(config.projectRoot);
  const requestedFindings = input.findingIds ?? [];
  const requestedRemediations = input.remediationIds ?? [];
  if (requestedFindings.some((id) => !all.some((record) => record.findingId === id)) || requestedRemediations.some((id) => !all.some((record) => record.remediationId === id))) return err('REMEDIATION_NOT_FOUND', 'A requested finding or remediation does not belong to the selected project root.');
  const selected = all.filter((record) => (requestedFindings.length === 0 || requestedFindings.includes(record.findingId)) && (requestedRemediations.length === 0 || requestedRemediations.includes(record.remediationId)));
  const latest = new Map<string, ControlledRemediationRecord>();
  for (const record of selected) latest.set(record.findingId, record);
  const records = [...latest.values()];
  if ((requestedFindings.length > 0 || requestedRemediations.length > 0) && records.length === 0) return err('REMEDIATION_CONFLICT', 'The requested finding and remediation selections do not identify the same current remediation.');
  if (requestedRemediations.some((id) => !records.some((record) => record.remediationId === id && all.filter((candidate) => candidate.findingId === record.findingId).at(-1)?.remediationId === id))) return err('REMEDIATION_CONFLICT', 'The requested remediation is superseded by a newer validated remediation for that finding.');
  const earliest = all[0];
  const baseline = earliest?.baselineFindings ?? [];
  const prior = new Map(records.map((record) => [record.remediationId, record.lastRetest?.result ?? null]));
  const runtimeRequired = records.some((record) => record.before.proofSupport === 'runtime');
  const setupBlocker = runtimeRequired && input.runtimeSetupFailure ? classifyRuntimeSetupFailure(input.runtimeSetupFailure.command, input.runtimeSetupFailure.output) : null;
  const retests = new Map<string, RetestFindingReceipt | null>();
  for (const record of records) {
    if (setupBlocker && record.before.proofSupport === 'runtime') { retests.set(record.remediationId, null); continue; }
    const outcome = await retestFinding(config, { findingId: record.findingId, target: input.target, sessions: input.sessions, sessionParams: input.sessionParams });
    retests.set(record.remediationId, outcome.ok ? outcome.data : null);
  }
  const scan = await scanProject(config);
  if (!scan.ok) return err('INTERNAL_ERROR', 'The post-remediation security scan did not complete.');
  const routes = discoverRoutes(config);
  const access = routes.ok ? analyzeAccessControl(config, routes.data.entries) : null;
  const current = [
    ...scan.data.findings.map((finding) => baselineFinding(finding, 'security_scan')),
    ...(access ? access.findings.map((finding) => baselineFinding(finding, 'access_control')) : []),
  ];
  const audit = await runSecurityAuditPipeline(config, { sessions: [], sessionParams: {}, maxProofAttempts: 1 });
  const unsupportedDomains = audit.ok ? audit.data.domainCoverage.filter((domain) => domain.status === 'unsupported' || domain.status === 'failed' || domain.status === 'skipped').map((domain) => domain.domain) : [];
  const postComplete = routes.ok && scan.data.project.support === 'supported' && !scan.data.fileAnalysis.inventoryTruncated && scan.data.fileAnalysis.skippedFiles.length === 0 && scan.data.rulesFailed.length === 0 && scan.data.rulesSkipped.length === 0 && audit.ok && audit.data.readOnly.sourceTreeUnchanged === true && audit.data.execution.findingsTruncated === 0;
  const buckets: SecurityRemediationSweepResult['findings'] = { resolved: [], stillVulnerable: [], inconclusive: [], unsupported: [], blocked: [] };
  const blockers: EnvironmentBlocker[] = [];
  if (setupBlocker) blockers.push(setupBlocker);
  for (const record of records) {
    const original = originalSnapshot(record);
    const retest = retests.get(record.remediationId) ?? null;
    const matches = original ? current.filter((finding) => sameCondition(original, finding)) : [];
    const possible = original ? current.filter((finding) => possibleCondition(original, finding)) : [];
    let state: SweepFinalState = 'inconclusive';
    let limitation: string | null = null;
    if (record.before.origin === 'unsupported' || record.before.proofSupport === 'requires-adapter') state = 'unsupported';
    else if (setupBlocker && record.before.proofSupport === 'runtime') { state = 'blocked'; limitation = setupBlocker.reason; }
    else if (retest?.result === 'not_verifiable') state = 'unsupported';
    else if (retest?.retestStatus === 'blocked') { state = 'blocked'; limitation = retest.blocker?.reason ?? null; if (retest.blocker) blockers.push(retest.blocker as EnvironmentBlocker); }
    else if (retest?.result === 'still_present') state = 'still_vulnerable';
    else if (matches.length > 0 && record.before.proofSupport !== 'runtime' && postComplete) { state = 'still_vulnerable'; limitation = 'The original rule-backed condition is present in the post-remediation scan.'; }
    else if (retest?.result === 'resolved' && retest.verification.verified && retest.retestStatus === 'completed' && postComplete && earliest?.baselineComplete && original && (record.before.proofSupport === 'runtime' || possible.length === 0)) state = 'resolved';
    else limitation = retest?.limitation ?? (possible.length > 0 ? 'The post-remediation scan contains a related finding that cannot be correlated confidently.' : 'Required baseline, retest, or post-scan evidence is incomplete.');
    const item: SweepFinding = { findingId: record.findingId, remediationId: record.remediationId, state, priorRetest: prior.get(record.remediationId) ?? null, evidence: { originalFindingId: record.before.sourceId, ruleId: record.before.ruleId, originalEvidenceHash: record.before.evidenceHash, validatedContentHash: record.appliedHash, validationStatus: 'passed', retest, postScanFindingIds: possible.map((finding) => finding.id) }, limitation };
    if (state === 'resolved') buckets.resolved.push(item);
    else if (state === 'still_vulnerable') buckets.stillVulnerable.push(item);
    else if (state === 'unsupported') buckets.unsupported.push(item);
    else if (state === 'blocked') buckets.blocked.push(item);
    else buckets.inconclusive.push(item);
  }
  const correlation = earliest?.baselineComplete ? correlatePostFindings(baseline, current) : { newFindings: [], uncertainFindings: [] };
  const { newFindings, uncertainFindings } = correlation;
  const blocked = buckets.blocked.length > 0;
  const securityStatus = buckets.stillVulnerable.length > 0 || newFindings.length > 0 ? 'vulnerable' : blocked || buckets.inconclusive.length > 0 || buckets.unsupported.length > 0 || current.length > 0 || !earliest?.baselineComplete || !postComplete || unsupportedDomains.length > 0 || records.length === 0 ? 'inconclusive' : 'secure';
  const executionStatus = blocked ? 'blocked' : runtimeRequired ? 'completed' : 'not_required';
  const nextStep = blockers[0] ? { action: blockers[0].recommendedNextStep, safeToRerun: true as const } : securityStatus === 'inconclusive' ? { action: 'Review incomplete evidence or unsupported coverage, then rerun the sweep after prerequisites are available.', safeToRerun: true as const } : null;
  return ok({ projectRoot: config.projectRoot, securityStatus, executionStatus, verification: { attempted: records.some((record) => retests.get(record.remediationId)?.verification.attempted), completed: records.length > 0 && !blocked && records.every((record) => retests.get(record.remediationId)?.verification.completed === true), blocked, verifiedVulnerabilities: buckets.stillVulnerable.filter((item) => item.evidence.retest?.verification.completed && item.evidence.retest.evidence.method.startsWith('runtime')).length, resolvedFindings: buckets.resolved.length, remainingFindings: buckets.stillVulnerable.length, inconclusiveFindings: buckets.inconclusive.length, unsupportedFindings: buckets.unsupported.length }, findings: buckets, newFindings, uncertainFindings, baseline: { findingCount: baseline.length, complete: earliest?.baselineComplete ?? false, remediationCount: records.length, pendingRetest: [...prior.values()].filter((value) => value === null).length, alreadyRetested: [...prior.values()].filter((value) => value !== null).length }, postSweep: { findingCount: current.length, complete: postComplete, auditReadOnly: audit.ok ? audit.data.readOnly.sourceTreeUnchanged : null, unsupportedDomains }, blockers, nextStep, limitations: !audit.ok ? ['The full audit pipeline did not complete.'] : [] });
}
