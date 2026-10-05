import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { AppConfig } from '../config.js';
import { logger } from '../logger.js';
import { runProjectDiscovery } from '../discovery/projectDiscovery.js';
import { discoverRoutes } from '../routes/engine.js';
import { scanProject } from '../security/scanner.js';
import { analyzeAccessControl } from '../access/engine.js';
import { runDeepSecurityAudit } from '../intelligence/engine.js';
import { buildSecurityGraph, listSecurityReceiptsForFinding, proveSecurityFinding } from '../proof/engine.js';
import type { SecurityGraph, SecurityReceipt } from '../proof/types.js';
import { listRemediationsForInvestigation } from '../remediation/engine.js';
import { getInvestigation } from '../investigation/orchestrator.js';
import { listFiles } from '../fs/fsOperations.js';
import { detachedRedacted } from '../report/redaction.js';
import { err, ok, type ToolOutcome } from '../types.js';
import type { RunFullSecurityAuditInput } from '../validation/schemas.js';
import { applyClassification } from './classify.js';
import { extendGraphWithAudit, findNearDuplicates } from './graph.js';
import { accessCategory, addOrMerge, canonicalCategory, compareBySeverity, compareFindings, createFinding, findingIdentity, fromAccessFinding, fromDeepFinding, fromSecurityFinding, normalizeFile, safeText, synthesizeEvidence } from './identity.js';
import { calculateRiskScore } from './scoring.js';
import { advance, advanceToVerified } from './lifecycle.js';
import { assessVerification } from './verification.js';
import type { AuditContext, AuditFinding, AuditGraphSummary, AuditResult, AuditStage, AuditSummary, FinalVerification, NamedCount, StageStatus, TreeFingerprint } from './types.js';

interface StageOutput {
  count: number;
  note?: string;
  status?: StageStatus;
}

const MAX_TRACKED_FINDINGS = 5_000;

const LIMITATIONS = [
  'Findings are static candidates unless a registered proof adapter produced a verified receipt from a semantic oracle against an operator-authorized local target.',
  'Deep-analysis findings are heuristic line patterns; they are not runtime-provable and remain static-only unless merged into a finding that a registered adapter handles.',
  'Each proof attempt re-derives the route inventory inside the proof engine; attempts are bounded by maxProofAttempts.',
  'The security graph is built from route, access-control, and audit lifecycle records; it is not an AST or taint graph.',
  'Remediation and replay status is reported only for the supplied investigationId and only for records held in this server process.',
  'Receipts and remediation records are held in memory and are not persisted across server restarts.',
];

function treeFingerprint(config: AppConfig): TreeFingerprint {
  const listed = listFiles(config, { dirPath: '.', recursive: true, maxResults: config.maxListResults });
  if (!listed.ok) return { hash: '', files: 0, truncated: false };
  const hash = crypto.createHash('sha256');
  let files = 0;
  for (const entry of [...listed.data].sort((a, b) => a.path.localeCompare(b.path))) {
    if (entry.type !== 'file') continue;
    try {
      const stat = fs.lstatSync(path.join(config.projectRoot, entry.path));
      hash.update(`${entry.path}|${stat.size}|${stat.mtimeMs}\n`);
    } catch {
      hash.update(`${entry.path}|missing\n`);
    }
    files += 1;
  }
  return { hash: hash.digest('hex'), files, truncated: listed.data.length >= config.maxListResults };
}

function createContext(config: AppConfig, input: RunFullSecurityAuditInput): AuditContext {
  const startedMs = Date.now();
  const limits = {
    maxFindings: input.maxFindings ?? 300,
    maxProofAttempts: input.maxProofAttempts ?? 5,
    maxElapsedMs: input.maxElapsedMs ?? 180_000,
    maxFiles: input.maxFiles ?? 2_000,
    maxEvidencePerFinding: 5,
  };
  let treeBefore: TreeFingerprint | null = null;
  try {
    treeBefore = treeFingerprint(config);
  } catch {
    treeBefore = null;
  }
  return {
    runId: `run-${crypto.randomUUID()}`,
    startedAt: new Date(startedMs).toISOString(),
    startedMs,
    deadlineMs: startedMs + limits.maxElapsedMs,
    limits,
    profile: null,
    routesOutcome: null,
    scanOutcome: null,
    access: null,
    deepCounts: null,
    findings: new Map(),
    sourceIndex: new Map(),
    receipts: new Map(),
    remediationRecords: [],
    graph: null,
    treeBefore,
    treeAfter: null,
    truncatedFindings: 0,
    issues: [],
    stages: [],
  };
}

function addIssue(ctx: AuditContext, stage: AuditStage, code: string, message: string, recoverable: boolean, affectedFindings: string[]): void {
  if (ctx.issues.length < 100) ctx.issues.push({ stage, code, message: safeText(message), recoverable, affectedFindings: affectedFindings.slice(0, 20) });
}

function pushStage(ctx: AuditContext, stage: AuditStage, status: StageStatus, startedMs: number, count: number, note: string | undefined): void {
  const finishedMs = Date.now();
  ctx.stages.push({ stage, status, startedAt: new Date(startedMs).toISOString(), finishedAt: new Date(finishedMs).toISOString(), durationMs: finishedMs - startedMs, itemCount: count, note: note ?? null });
}

async function runStage(ctx: AuditContext, stage: AuditStage, recoverable: boolean, enforceDeadline: boolean, body: () => Promise<StageOutput> | StageOutput): Promise<boolean> {
  const started = Date.now();
  if (enforceDeadline && started > ctx.deadlineMs) {
    pushStage(ctx, stage, 'blocked', started, 0, 'The audit elapsed-time limit was reached before this stage.');
    addIssue(ctx, stage, 'BUDGET_EXCEEDED', 'The audit elapsed-time limit was reached; this stage did not run.', true, []);
    return false;
  }
  try {
    const output = await body();
    const status = output.status ?? 'completed';
    pushStage(ctx, stage, status, started, output.count, output.note);
    return status === 'completed';
  } catch (error) {
    logger.error('audit_stage_failed', { stage, errorName: error instanceof Error ? error.name : 'unknown' });
    pushStage(ctx, stage, 'failed', started, 0, 'The stage failed unexpectedly.');
    addIssue(ctx, stage, 'STAGE_FAILED', `The ${stage} stage failed unexpectedly.`, recoverable, []);
    return false;
  }
}

function skipStage(ctx: AuditContext, stage: AuditStage, note: string): void {
  pushStage(ctx, stage, 'skipped', Date.now(), 0, note);
}

function collect(ctx: AuditContext, finding: AuditFinding): boolean {
  const existed = ctx.findings.has(finding.id);
  if (!existed && ctx.findings.size >= MAX_TRACKED_FINDINGS) return false;
  addOrMerge(ctx.findings, finding);
  for (const source of finding.sources) ctx.sourceIndex.set(source.sourceId, finding.id);
  return existed;
}

function scopeReceipts(list: SecurityReceipt[], target: { allowedOrigin: string } | undefined): SecurityReceipt[] {
  if (!target) return list;
  return list.filter((receipt) => receipt.targetOrigin === target.allowedOrigin);
}

function applyReceipts(finding: AuditFinding, receipts: SecurityReceipt[], ranNow: boolean, expectedOrigin?: string, projectRoot?: string): void {
  finding.proof.receiptIds = receipts.map((receipt) => receipt.receiptId).slice(0, 10);
  const originals = receipts.filter((receipt) => receipt.replayOfReceiptId === null);
  const replays = receipts.filter((receipt) => receipt.replayOfReceiptId !== null);
  const chosen = [...originals].reverse().find((receipt) => receipt.status === 'verified') ?? originals[originals.length - 1] ?? null;
  const replay = replays[replays.length - 1] ?? null;
  if (replay) finding.replay = { status: replay.status, receiptId: replay.receiptId };
  if (!chosen) return;
  finding.proof.status = chosen.status;
  finding.proof.fromPriorReceipt = !ranNow;
  finding.proof.note = chosen.status === 'verified' ? null : chosen.limitation ? safeText(chosen.limitation) : null;
  finding.classification.proofStatus = chosen.status;
  if (chosen.status === 'verified') advanceToVerified(finding, chosen, expectedOrigin, projectRoot);
  else if (chosen.status === 'not_reproduced') advance(finding, 'not_reproduced');
  else if (chosen.status === 'inconclusive') advance(finding, 'inconclusive');
  else advance(finding, 'blocked');
}

function reconcileRemediation(ctx: AuditContext): void {
  for (const finding of ctx.findings.values()) {
    const sourceIds = new Set(finding.sources.map((source) => source.sourceId));
    const records = ctx.remediationRecords.filter((record) => sourceIds.has(record.proposal.findingId));
    if (records.length === 0) continue;
    const latest = records[records.length - 1];
    finding.remediation = { status: latest.status, remediationIds: records.map((record) => record.proposal.proposalId).slice(0, 10) };
    if (finding.status !== 'verified') continue;
    try {
      if (latest.status === 'verified_resolved' && latest.verification?.replayResult === 'resolved' && finding.replay.status === 'not_reproduced') {
        advance(finding, 'remediation_applied');
        advance(finding, 'verified_resolved');
      } else if (latest.status === 'applied_pending_verification' || latest.status === 'verifying') {
        advance(finding, 'remediation_applied');
      }
    } catch {
      addIssue(ctx, 'runtime_proof', 'LIFECYCLE_VIOLATION', 'A remediation record could not be applied to the finding lifecycle.', true, [finding.id]);
    }
  }
}

function collectResolved(ctx: AuditContext, investigationId: string, config: AppConfig): void {
  const inv = getInvestigation(investigationId, config);
  if (!inv.ok) return;
  const current = new Set([...ctx.findings.values()].flatMap((finding) => finding.sources.map((source) => source.sourceId)));
  for (const record of ctx.remediationRecords) {
    const sourceId = record.proposal.findingId;
    if (record.status !== 'verified_resolved' || record.verification?.replayResult !== 'resolved' || current.has(sourceId)) continue;
    const view = inv.data.findings.find((item) => item.findingId === sourceId);
    if (!view) continue;
    const receipts = listSecurityReceiptsForFinding(sourceId, config.projectRoot);
    const original = receipts.find((receipt) => receipt.replayOfReceiptId === null && receipt.status === 'verified');
    const replay = [...receipts].reverse().find((receipt) => original !== undefined && receipt.replayOfReceiptId === original.receiptId && receipt.status === 'not_reproduced');
    if (!original || !replay || original.targetOrigin === undefined || original.targetOrigin !== replay.targetOrigin) continue;
    const file = normalizeFile(view.file || record.proposal.files[0]?.path || null);
    const route = view.path ? view.path : null;
    const category = view.origin === 'access_control' ? accessCategory(view.candidateType, view.category) : canonicalCategory(view.category);
    const finding = createFinding({
      id: findingIdentity({ category, file, line: null, route, title: view.title }),
      category,
      title: safeText(view.title),
      severity: view.severity,
      confidence: view.confidence,
      file,
      line: null,
      route,
      routeId: view.routeId || null,
      sources: [{ stage: 'runtime_proof', origin: 'remediation_record', sourceId, ruleId: null, category: original.proofCase.type, candidateType: null, routePath: null }],
      evidence: [safeText(record.verification?.summary ?? 'Remediation verified.'), safeText(original.whyProven)],
      recommendation: safeText(record.proposal.description),
    });
    finding.classification = { proofSupport: 'runtime', proofStatus: 'verified', adapter: original.proofCase.type, proofSourceId: sourceId, prerequisites: [], maxRequests: original.proofCase.maxRequests, reason: 'Reconstructed from a verified original receipt, a controlled remediation, and a not_reproduced replay receipt.' };
    try {
      advance(finding, 'analyzed');
      advance(finding, 'proof_eligible');
      advanceToVerified(finding, original, original.targetOrigin, config.projectRoot);
      advance(finding, 'remediation_applied');
      advance(finding, 'verified_resolved');
    } catch {
      continue;
    }
    finding.proof = { receiptIds: receipts.map((receipt) => receipt.receiptId).slice(0, 10), status: 'verified', attempted: false, fromPriorReceipt: true, note: null };
    finding.remediation = { status: record.status, remediationIds: [record.proposal.proposalId] };
    finding.replay = { status: replay.status, receiptId: replay.receiptId };
    ctx.receipts.set(finding.id, receipts);
    addOrMerge(ctx.findings, finding);
  }
}

function tally(values: string[]): NamedCount[] {
  const counts = new Map<string, number>();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([name, count]) => ({ name, count }));
}

function summarizeGraph(graph: SecurityGraph | null, include: boolean): AuditGraphSummary {
  if (!graph) return { built: false, nodeCount: 0, edgeCount: 0, nodeKinds: [], edgeRelations: [], limitations: ['The security graph was not built in this run.'] };
  const summary: AuditGraphSummary = {
    built: true,
    nodeCount: graph.nodes.length,
    edgeCount: graph.edges.length,
    nodeKinds: tally(graph.nodes.map((node) => node.kind)),
    edgeRelations: tally(graph.edges.map((edge) => edge.relation)),
    limitations: graph.limitations,
  };
  if (include) {
    summary.nodes = graph.nodes.slice(0, 1_000);
    summary.edges = graph.edges.slice(0, 1_000);
  }
  return summary;
}

function buildResult(ctx: AuditContext, input: RunFullSecurityAuditInput): AuditResult {
  const findings = [...ctx.findings.values()].sort(compareFindings);
  for (const finding of findings) {
    finding.sources.sort((a, b) => a.origin.localeCompare(b.origin) || a.sourceId.localeCompare(b.sourceId));
    finding.verification = assessVerification(finding);
  }
  const count = (predicate: (finding: AuditFinding) => boolean): number => findings.filter(predicate).length;
  const summary: AuditSummary = {
    total: findings.length,
    bySeverity: {
      critical: count((f) => f.severity === 'critical'),
      high: count((f) => f.severity === 'high'),
      medium: count((f) => f.severity === 'medium'),
      low: count((f) => f.severity === 'low'),
      informational: count((f) => f.severity === 'info'),
    },
    runtimeVerified: count((f) => f.status === 'verified'),
    staticOnly: count((f) => f.classification.proofSupport === 'static-only'),
    unsupported: count((f) => f.status === 'unsupported'),
    blocked: count((f) => f.status === 'blocked'),
    inconclusive: count((f) => f.status === 'inconclusive'),
    resolved: count((f) => f.status === 'verified_resolved'),
    byStatus: tally(findings.map((f) => f.status)),
    byCategory: tally(findings.map((f) => f.category)),
  };
  const finalVerification: FinalVerification =
    findings.length === 0 ? 'no_findings'
    : summary.runtimeVerified > 0 ? 'verified_findings_present'
    : summary.resolved === findings.length ? 'all_verified_resolved'
    : 'candidates_unverified';
  const auditId = `audit-${crypto.createHash('sha256').update([ctx.profile?.projectName ?? '', ...findings.map((f) => `${f.id}:${f.status}`)].join('|')).digest('hex').slice(0, 20)}`;
  const finishedMs = Date.now();
  const before = ctx.treeBefore;
  const after = ctx.treeAfter;
  const comparable = before !== null && after !== null && before.hash.length > 0 && after.hash.length > 0;
  return {
    schemaVersion: 1,
    auditId,
    runId: ctx.runId,
    readOnly: { enforced: true, sourceTreeUnchanged: comparable ? before.hash === after.hash : null, filesChecked: before?.files ?? 0, truncated: before?.truncated ?? false },
    project: { name: ctx.profile?.projectName ?? null, ecosystem: ctx.profile?.ecosystem ?? 'unknown', root: '[CONFIGURED_PROJECT_ROOT]' },
    execution: { startedAt: ctx.startedAt, finishedAt: new Date(finishedMs).toISOString(), elapsedMs: finishedMs - ctx.startedMs, limits: ctx.limits, findingsTruncated: ctx.truncatedFindings },
    stages: ctx.stages,
    summary,
    findings,
    nearDuplicates: findNearDuplicates(findings),
    graph: summarizeGraph(ctx.graph, input.includeGraph === true),
    remediation: { investigationId: input.investigationId ?? null, records: ctx.remediationRecords.length, resolved: summary.resolved },
    finalVerification,
    report: {
      reportId: `report-${auditId}`,
      generatedAt: new Date(finishedMs).toISOString(),
      schemaVersion: 1,
      summaryNote: 'runtimeVerified counts findings whose status is verified; staticOnly counts findings with no proof adapter class; unsupported counts findings with lifecycle status unsupported; resolved counts verified_resolved.',
    },
    issues: ctx.issues,
    limitations: LIMITATIONS,
  };
}

export async function runSecurityAuditPipeline(config: AppConfig, input: RunFullSecurityAuditInput): Promise<ToolOutcome<AuditResult>> {
  const ctx = createContext(config, input);

  await runStage(ctx, 'discovery', true, true, () => {
    ctx.profile = runProjectDiscovery(config.projectRoot);
    return { count: ctx.treeBefore?.files ?? 0, note: ctx.treeBefore?.truncated ? 'File listing reached the configured limit.' : undefined };
  });

  await runStage(ctx, 'route_discovery', true, true, () => {
    const outcome = discoverRoutes(config);
    ctx.routesOutcome = outcome;
    if (!outcome.ok) {
      addIssue(ctx, 'route_discovery', 'ROUTE_DISCOVERY_FAILED', outcome.error.message, true, []);
      return { count: 0, status: 'failed', note: 'Route discovery returned an error.' };
    }
    return { count: outcome.data.entries.length };
  });

  await runStage(ctx, 'static_scan', true, true, async () => {
    const outcome = await scanProject(config);
    ctx.scanOutcome = outcome;
    if (!outcome.ok) {
      addIssue(ctx, 'static_scan', 'STATIC_SCAN_FAILED', outcome.error.message, true, []);
      return { count: 0, status: 'failed', note: 'The static scan returned an error.' };
    }
    for (const finding of outcome.data.findings) collect(ctx, fromSecurityFinding(finding));
    return { count: outcome.data.findings.length, note: outcome.data.warnings.length > 0 ? `${outcome.data.warnings.length} scanner warning(s).` : undefined };
  });

  const routes = ctx.routesOutcome;
  if (!routes || !routes.ok) {
    skipStage(ctx, 'access_control', 'Route discovery did not produce an inventory.');
  } else {
    await runStage(ctx, 'access_control', true, true, () => {
      const result = analyzeAccessControl(config, routes.data.entries);
      ctx.access = result;
      for (const finding of result.findings) collect(ctx, fromAccessFinding(finding));
      return { count: result.findings.length };
    });
  }

  await runStage(ctx, 'deep_analysis', true, true, async () => {
    const shared = ctx.profile && ctx.routesOutcome && ctx.scanOutcome ? { profile: ctx.profile, scan: ctx.scanOutcome, routes: ctx.routesOutcome, access: ctx.access } : undefined;
    const outcome = await runDeepSecurityAudit(config, { maxFiles: ctx.limits.maxFiles, shared });
    if (!outcome.ok) {
      addIssue(ctx, 'deep_analysis', 'DEEP_ANALYSIS_FAILED', outcome.error.message, true, []);
      return { count: 0, status: 'failed', note: 'Deep analysis returned an error.' };
    }
    ctx.deepCounts = { findings: outcome.data.findings.length, evidence: outcome.data.evidence.length };
    const evidenceById = new Map(outcome.data.evidence.map((item) => [item.id, item] as const));
    let merged = 0;
    let added = 0;
    for (const deep of outcome.data.findings) {
      const converted = fromDeepFinding(deep, evidenceById, ctx.sourceIndex);
      if (!converted) continue;
      if (collect(ctx, converted)) merged += 1; else added += 1;
    }
    return { count: outcome.data.findings.length, note: `${merged} merged into existing findings, ${added} new.` };
  });

  await runStage(ctx, 'candidate_classification', false, false, () => {
    const ordered = [...ctx.findings.values()].sort(compareBySeverity);
    if (ordered.length > ctx.limits.maxFindings) {
      for (const dropped of ordered.slice(ctx.limits.maxFindings)) ctx.findings.delete(dropped.id);
      ctx.truncatedFindings = ordered.length - ctx.limits.maxFindings;
      addIssue(ctx, 'candidate_classification', 'FINDINGS_TRUNCATED', `${ctx.truncatedFindings} lower-priority finding(s) were omitted by the maxFindings limit.`, true, []);
    }
    let eligible = 0;
    let blocked = 0;
    let unsupported = 0;
    for (const finding of ctx.findings.values()) {
      advance(finding, 'analyzed');
      applyClassification(finding, ctx.routesOutcome && ctx.routesOutcome.ok ? ctx.routesOutcome.data.entries : undefined);
      if (finding.status === 'proof_eligible') eligible += 1;
      else if (finding.status === 'blocked') blocked += 1;
      else unsupported += 1;
    }
    return { count: ctx.findings.size, note: `${eligible} proof-eligible, ${unsupported} unsupported, ${blocked} blocked.` };
  });

  await runStage(ctx, 'runtime_proof', true, true, async () => {
    const eligible = [...ctx.findings.values()].filter((finding) => finding.status === 'proof_eligible').sort(compareBySeverity);
    const target = input.target;
    const attempted = new Set<string>();
    const notAttempted: string[] = [];
    let attempts = 0;
    let reused = 0;
    for (const finding of eligible) {
      const sourceId = finding.classification.proofSourceId;
      if (!sourceId) continue;
      let receipts = scopeReceipts(listSecurityReceiptsForFinding(sourceId, config.projectRoot), target);
      const hasVerified = receipts.some((receipt) => receipt.replayOfReceiptId === null && receipt.status === 'verified');
      let ranNow = false;
      if (!hasVerified && target) {
        if (attempts >= ctx.limits.maxProofAttempts || Date.now() > ctx.deadlineMs) {
          notAttempted.push(finding.id);
        } else if (!attempted.has(sourceId)) {
          attempted.add(sourceId);
          attempts += 1;
          try {
            const outcome = await proveSecurityFinding(config, { findingId: sourceId, target, sessions: input.sessions, sessionParams: input.sessionParams });
            if (outcome.ok) {
              receipts = scopeReceipts(listSecurityReceiptsForFinding(sourceId, config.projectRoot), target);
              ranNow = true;
            } else {
              addIssue(ctx, 'runtime_proof', 'PROOF_DISPATCH_FAILED', outcome.error.message, true, [finding.id]);
            }
          } catch {
            addIssue(ctx, 'runtime_proof', 'PROOF_DISPATCH_FAILED', 'Proof dispatch failed unexpectedly.', true, [finding.id]);
          }
        }
      }
      if (ranNow) finding.proof.attempted = true;
      else if (receipts.length > 0) reused += 1;
      ctx.receipts.set(finding.id, receipts);
      try {
        applyReceipts(finding, receipts, ranNow, target?.allowedOrigin, config.projectRoot);
      } catch {
        addIssue(ctx, 'runtime_proof', 'LIFECYCLE_VIOLATION', 'A proof receipt could not be applied to the finding lifecycle.', true, [finding.id]);
      }
    }
    if (notAttempted.length > 0) addIssue(ctx, 'runtime_proof', 'PROOF_ATTEMPT_LIMIT', `${notAttempted.length} eligible finding(s) were not attempted because of the proof attempt or time limit.`, true, notAttempted);
    if (input.investigationId) {
      const investigation = getInvestigation(input.investigationId, config);
      if (investigation.ok) {
        ctx.remediationRecords = listRemediationsForInvestigation(input.investigationId).slice(0, 100);
        reconcileRemediation(ctx);
        collectResolved(ctx, input.investigationId, config);
      } else {
        addIssue(ctx, 'runtime_proof', 'INVESTIGATION_UNAVAILABLE', investigation.error.message, true, []);
      }
    }
    const idle = !target && reused === 0;
    return {
      count: attempts + reused,
      status: idle ? 'skipped' : 'completed',
      note: idle ? 'No authorized runtime target supplied and no prior receipts; eligible findings remain proof_eligible.' : `${attempts} proof attempt(s) executed, ${reused} finding(s) used prior receipts.`,
    };
  });

  for (const finding of ctx.findings.values()) {
    finding.riskScore = calculateRiskScore(finding);
    finding.evidenceSynthesis = synthesizeEvidence(finding);
  }

  await runStage(ctx, 'graph_construction', true, true, () => {
    const routeOutcome = ctx.routesOutcome;
    if (!ctx.profile || !routeOutcome || !routeOutcome.ok) return { count: 0, status: 'skipped', note: 'Route inventory unavailable.' };
    const base = buildSecurityGraph(config, { profile: ctx.profile, routes: routeOutcome, access: ctx.access });
    if (!base.ok) {
      addIssue(ctx, 'graph_construction', 'GRAPH_BUILD_FAILED', base.error.message, true, []);
      return { count: 0, status: 'failed', note: 'Graph construction returned an error.' };
    }
    const receiptRefs = new Map([...ctx.receipts.entries()].map(([id, list]) => [id, list.map((receipt) => ({ receiptId: receipt.receiptId, status: receipt.status }))] as const));
    ctx.graph = extendGraphWithAudit(base.data, [...ctx.findings.values()], ctx.access?.matrix ?? [], receiptRefs);
    return { count: ctx.graph.nodes.length };
  });

  try {
    ctx.treeAfter = treeFingerprint(config);
  } catch {
    ctx.treeAfter = null;
  }
  const reportStarted = Date.now();
  pushStage(ctx, 'report', 'completed', reportStarted, ctx.findings.size, undefined);
  try {
    return ok(detachedRedacted(buildResult(ctx, input)));
  } catch (error) {
    logger.error('audit_report_failed', { errorName: error instanceof Error ? error.name : 'unknown' });
    return err('INTERNAL_ERROR', 'The audit report could not be assembled.');
  }
}
