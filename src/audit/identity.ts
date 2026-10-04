import crypto from 'node:crypto';
import type { AccessControlFinding } from '../access/types.js';
import type { IntelligenceEvidence, IntelligenceFinding } from '../intelligence/types.js';
import { redactReportValue } from '../report/redaction.js';
import { redactSecurityText } from '../security/utils.js';
import { hasUnresolvedSegment } from '../runtime/cases/common.js';
import type { SecurityFinding } from '../security/types.js';
import { AUDIT_STAGES, type AuditFinding, type AuditStage, type Confidence, type FindingCorrelation, type FindingSource, type Severity } from './types.js';

export const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const CONFIDENCE_RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };
export const MAX_EVIDENCE_ITEMS = 5;
const MAX_EVIDENCE_CHARS = 300;

const CATEGORY_ALIASES: Record<string, string> = {
  command_execution: 'command_injection',
  insecure_redirects: 'open_redirect',
  security_headers: 'security_configuration',
  session_cookies: 'security_configuration',
  docker: 'security_configuration',
  ci_cd: 'security_configuration',
  environment_configuration: 'configuration_secrets',
  npm_scripts: 'dependency_risk',
  dependency_supply_chain: 'dependency_risk',
  jwt: 'authentication',
  cryptography: 'weak_cryptography',
  idor: 'idor_bola',
};

const ACCESS_CATEGORIES: Record<string, string> = {
  missing_authentication: 'missing_authentication',
  missing_authorization: 'missing_authorization',
  idor_candidate: 'idor_bola',
  user_resource_access: 'idor_bola',
  inconsistent_authorization: 'authorization_inconsistency',
};

export function safeText(value: unknown): string {
  return redactSecurityText(String(redactReportValue(String(value ?? '')))).replace(/\s+/g, ' ').trim().slice(0, MAX_EVIDENCE_CHARS);
}

export function canonicalCategory(raw: string): string {
  const key = raw.trim().toLowerCase();
  return CATEGORY_ALIASES[key] ?? key;
}

export function accessCategory(candidateType: string, fallback: string): string {
  return ACCESS_CATEGORIES[candidateType] ?? canonicalCategory(fallback);
}

export function normalizeFile(file: string | null | undefined): string | null {
  if (!file) return null;
  const normalized = file.replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/{2,}/g, '/');
  return normalized.length > 0 ? normalized : null;
}

export function normalizeRoute(method: string, routePath: string): string {
  const trimmed = routePath.trim().replace(/\/+$/, '');
  return `${method.toUpperCase()} ${trimmed.length > 0 ? trimmed : '/'}`;
}

export function findingIdentity(input: { category: string; file: string | null; line: number | null; route: string | null; title: string }): string {
  const parts = [canonicalCategory(input.category), normalizeFile(input.file) ?? '', input.route ?? '', input.line === null ? '' : String(input.line)];
  if (parts[1] === '' && parts[2] === '') parts.push(input.title.trim().toLowerCase().replace(/\s+/g, ' ').slice(0, 200));
  return `cs-${crypto.createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 20)}`;
}

export function stagesOf(sources: FindingSource[]): AuditStage[] {
  return AUDIT_STAGES.filter((stage) => sources.some((source) => source.stage === stage));
}

export function compareFindings(a: AuditFinding, b: AuditFinding): number {
  const aScore = a.riskScore ?? 0;
  const bScore = b.riskScore ?? 0;
  if (aScore !== bScore) return bScore - aScore;
  return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.id.localeCompare(b.id);
}

export function createFinding(input: {
  id: string;
  category: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  file: string | null;
  line: number | null;
  route: string | null;
  routeId: string | null;
  sources: FindingSource[];
  evidence: string[];
  recommendation: string;
}): AuditFinding {
  const evidence = input.evidence.filter((item) => item.length > 0).slice(0, MAX_EVIDENCE_ITEMS);
  return {
    ...input,
    evidence: evidence.length > 0 ? evidence : [safeText(input.title)],
    stages: stagesOf(input.sources),
    status: 'candidate',
    classification: { proofSupport: 'static-only', proofStatus: 'unsupported', adapter: null, proofSourceId: null, prerequisites: [], maxRequests: 0, reason: 'Not yet classified.' },
    proof: { receiptIds: [], status: null, attempted: false, fromPriorReceipt: false, note: null },
    remediation: { status: null, remediationIds: [] },
    replay: { status: 'not_attempted', receiptId: null },
  };
}

export function fromSecurityFinding(finding: SecurityFinding): AuditFinding {
  const file = normalizeFile(finding.file);
  const line = finding.line ?? null;
  return createFinding({
    id: findingIdentity({ category: finding.category, file, line, route: null, title: finding.title }),
    category: canonicalCategory(finding.category),
    title: safeText(finding.title),
    severity: finding.severity,
    confidence: finding.confidence,
    file,
    line,
    route: null,
    routeId: null,
    sources: [{ stage: 'static_scan', origin: 'security_scan', sourceId: finding.id, ruleId: finding.ruleId, category: finding.category, candidateType: null, routePath: null }],
    evidence: finding.evidence.map((item) => safeText(item.reason)),
    recommendation: safeText(finding.remediation),
  });
}

export function fromAccessFinding(finding: AccessControlFinding): AuditFinding {
  const file = normalizeFile(finding.file);
  const route = normalizeRoute(finding.method, finding.path);
  const resolved = finding.path !== 'unknown' && !hasUnresolvedSegment(finding.path);
  const category = accessCategory(finding.candidateType, finding.category);
  return createFinding({
    id: findingIdentity({ category, file, line: resolved ? null : finding.line, route, title: finding.title }),
    category,
    title: safeText(finding.title),
    severity: finding.severity,
    confidence: finding.confidence,
    file,
    line: finding.line,
    route,
    routeId: finding.routeId,
    sources: [{ stage: 'access_control', origin: 'access_control', sourceId: finding.id, ruleId: finding.ruleId, category: finding.category, candidateType: finding.candidateType, routePath: finding.path }],
    evidence: [safeText(finding.explanation), ...finding.evidence.map((item) => safeText(item.reason))],
    recommendation: safeText(finding.remediation),
  });
}

export function fromDeepFinding(finding: IntelligenceFinding, evidenceById: Map<string, IntelligenceEvidence>, sourceIndex: Map<string, string>): AuditFinding | null {
  const evidence = finding.evidenceIds.map((id) => evidenceById.get(id)).filter((item): item is IntelligenceEvidence => item !== undefined);
  const linked = evidence.find((item) => (item.kind === 'static_scan' || item.kind === 'access_control') && sourceIndex.has(item.sourceRef));
  const primary = evidence[0];
  const file = normalizeFile(primary?.file ?? finding.sourceRefs[0] ?? null);
  const line = primary?.line ?? null;
  const id = linked ? (sourceIndex.get(linked.sourceRef) as string) : findingIdentity({ category: finding.domain, file, line, route: null, title: finding.title });
  return createFinding({
    id,
    category: canonicalCategory(finding.domain),
    title: safeText(finding.title),
    severity: finding.severity,
    confidence: finding.confidence,
    file,
    line,
    route: null,
    routeId: null,
    sources: [{ stage: 'deep_analysis', origin: 'deep_analysis', sourceId: finding.id, ruleId: null, category: finding.domain, candidateType: null, routePath: null }],
    evidence: [safeText(finding.description), ...evidence.map((item) => safeText(item.detail))],
    recommendation: safeText(finding.remediation),
  });
}

function buildCorrelationReason(origins: Set<string>): string {
  const parts: string[] = [];
  if (origins.has('security_scan')) parts.push('Static scanner');
  if (origins.has('access_control')) parts.push('Access-control analysis');
  if (origins.has('deep_analysis')) parts.push('Deep heuristic analysis');
  return parts.join(' + ');
}

function updateCorrelationMetadata(existing: AuditFinding): void {
  const origins = new Set(existing.sources.map((s) => s.origin));
  const sourceIds = existing.sources.map((s) => s.sourceId).filter((id, i, arr) => arr.indexOf(id) === i).sort();
  
  if (sourceIds.length > 1 || origins.size > 1) {
    existing.correlation = {
      sourceIds,
      reason: buildCorrelationReason(origins),
      engineCount: origins.size,
    };
  }
}

export function addOrMerge(map: Map<string, AuditFinding>, incoming: AuditFinding): void {
  const existing = map.get(incoming.id);
  if (!existing) {
    map.set(incoming.id, incoming);
    updateCorrelationMetadata(incoming);
    return;
  }
  const heuristic = (item: AuditFinding): boolean => item.sources.every((source) => source.origin === 'deep_analysis');
  if (heuristic(existing) && !heuristic(incoming)) {
    existing.severity = incoming.severity;
    existing.title = incoming.title;
    existing.confidence = incoming.confidence;
  } else if (!heuristic(incoming)) {
    if (SEVERITY_RANK[incoming.severity] > SEVERITY_RANK[existing.severity]) {
      existing.severity = incoming.severity;
      existing.title = incoming.title;
    }
    if (CONFIDENCE_RANK[incoming.confidence] > CONFIDENCE_RANK[existing.confidence]) existing.confidence = incoming.confidence;
  }
  for (const source of incoming.sources) {
    if (!existing.sources.some((item) => item.origin === source.origin && item.sourceId === source.sourceId)) existing.sources.push(source);
  }
  for (const item of incoming.evidence) {
    if (existing.evidence.length < MAX_EVIDENCE_ITEMS && !existing.evidence.includes(item)) existing.evidence.push(item);
  }
  existing.file ??= incoming.file;
  existing.route ??= incoming.route;
  existing.routeId ??= incoming.routeId;
  if (incoming.line !== null && (existing.line === null || incoming.line < existing.line)) existing.line = incoming.line;
  if (existing.recommendation.length === 0) existing.recommendation = incoming.recommendation;
  existing.stages = stagesOf(existing.sources);
  updateCorrelationMetadata(existing);
}
