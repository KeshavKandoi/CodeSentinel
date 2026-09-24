import { createHash } from 'node:crypto';
import type { AppConfig } from '../config.js';
import { runProjectDiscovery } from '../discovery/projectDiscovery.js';
import type { Confidence, Evidence } from '../discovery/types.js';
import { createAdapterContext } from '../routes/sourceIndex.js';
import type { AttackSurfaceEntry, RouteFramework } from '../routes/types.js';
import type { SecurityEvidence, SecuritySeverity } from '../security/types.js';
import { collectEntryControls, createControlShared } from './controls.js';
import { collectGlobalGuards } from './globals.js';
import { collectIdentitySources } from './identity.js';
import { analyzeOwnership } from './ownership.js';
import { createSourceResolver } from './text.js';
import type {
  AccessControlEntry,
  AccessControlFinding,
  AccessControlSummary,
  AccessRuleMetadata,
  AccessState,
  AnalyzeAccessControlResult,
  AuthControl,
  AuthorizationControl,
  FindingCandidateType,
  IdentitySource,
  ResourceOwnershipCheck,
} from './types.js';

/**
 * Phase 5 entry point: orchestrates the existing access/* building blocks
 * (controls.ts, identity.ts, ownership.ts, globals.ts, text.ts) into a
 * single normalized AnalyzeAccessControlResult. Consumes the Phase 4
 * AttackSurfaceEntry[] rather than rediscovering routes. Static and
 * read-only: never starts the application, sends requests, or executes
 * project code. Never asserts a finding is confirmed -- everything
 * produced here is `status: 'suspected'`, left for Phase 6 to verify.
 */

const CONFIDENCE_RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };

function weaker(a: Confidence, b: Confidence): Confidence {
  return CONFIDENCE_RANK[a] <= CONFIDENCE_RANK[b] ? a : b;
}

const ADMIN_PATH_RE = /\/(admin|administration|internal|manage|moderation)(\/|$)/i;
const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const PUBLIC_PATH_HINT_RE =
  /\/(login|logout|register|signup|sign-up|health|healthz|status|ping|public|forgot-password|reset-password|webhook|callback)(\/|$)/i;

function isAdministrative(path: string, authorization: readonly AuthorizationControl[]): boolean {
  if (ADMIN_PATH_RE.test(path)) return true;
  return authorization.some(
    (a) => (a.kind === 'role' || a.kind === 'admin_flag') && a.requirement !== null && /admin|staff|superuser/i.test(a.requirement)
  );
}

function classifyState(
  explicitlyPublic: boolean,
  authentication: readonly AuthControl[],
  authorization: readonly AuthorizationControl[],
  ownership: readonly ResourceOwnershipCheck[],
  resolved: boolean
): AccessState {
  if (!resolved) return 'unknown';
  const hasAuthn = authentication.length > 0;
  const hasOwnership = ownership.length > 0;
  if (explicitlyPublic) {
    return hasAuthn || authorization.length > 0 ? 'mixed' : 'public';
  }
  if (hasOwnership && hasAuthn) return 'ownership_protected';
  if (authorization.some((a) => a.kind === 'role' || a.kind === 'admin_flag')) return 'role_protected';
  if (authorization.some((a) => a.kind === 'permission' || a.kind === 'scope' || a.kind === 'policy' || a.kind === 'tenant')) {
    return 'permission_protected';
  }
  if (hasAuthn) return 'authenticated';
  return 'public';
}

function entryConfidence(
  base: Confidence,
  authentication: readonly AuthControl[],
  authorization: readonly AuthorizationControl[]
): Confidence {
  let c = base;
  for (const a of authentication) c = weaker(c, a.confidence);
  for (const a of authorization) c = weaker(c, a.confidence);
  return c;
}

function toSecurityEvidence(file: string, line: number, reason: string): SecurityEvidence {
  return { file, line, reason };
}

function normalizeResourcePath(path: string): string {
  return path
    .split('/')
    .map((seg) => (/[:{<[]/.test(seg) ? '*' : seg))
    .join('/');
}

const ACCESS_RULES: Record<FindingCandidateType, AccessRuleMetadata> = {
  missing_authentication: {
    id: 'CS-ACCESS-001',
    title: 'Missing authentication on a sensitive route',
    category: 'authentication',
    severity: 'high',
    confidence: 'medium',
    candidateType: 'missing_authentication',
    description:
      'A state-changing route or an administrative route has no detected authentication control (no guard, middleware, decorator, or session/token check found in the analyzed source).',
    remediation: 'Require authentication (session, JWT, API key, etc.) before this handler executes.',
    falsePositiveGuidance:
      'Authentication may be enforced globally, by an upstream gateway/proxy, or by infrastructure not visible in this repository.',
  },
  missing_authorization: {
    id: 'CS-ACCESS-002',
    title: 'Administrative route without an authorization check',
    category: 'authorization',
    severity: 'high',
    confidence: 'medium',
    candidateType: 'missing_authorization',
    description:
      'A route that appears administrative or privileged has an authentication control but no detected role, permission, or policy check restricting who may call it.',
    remediation: 'Add a role/permission/policy check restricting this route to authorized users.',
    falsePositiveGuidance: 'Authorization may be enforced globally, by a proxy, or by an access-control layer not visible in this repository.',
  },
  idor_candidate: {
    id: 'CS-ACCESS-003',
    title: 'Resource written or deleted by identifier without an ownership check',
    category: 'authorization',
    severity: 'high',
    confidence: 'medium',
    candidateType: 'idor_candidate',
    description:
      'A resource is loaded using a caller-supplied identifier and then modified or deleted without a visible ownership/tenant comparison against the authenticated identity.',
    remediation: 'Scope the resource lookup to the authenticated identity, or explicitly compare resource ownership before allowing the write/delete.',
    falsePositiveGuidance:
      'Ownership may be enforced at the data layer, in a service class not analyzed here, or the resource may intentionally be shared.',
  },
  user_resource_access: {
    id: 'CS-ACCESS-004',
    title: 'Resource read by identifier without an ownership check',
    category: 'authorization',
    severity: 'medium',
    confidence: 'low',
    candidateType: 'user_resource_access',
    description:
      'A resource is read using a caller-supplied identifier without a visible ownership/tenant comparison against the authenticated identity.',
    remediation: 'Scope the read to the authenticated identity if the resource is user-specific, or confirm the resource is intentionally shared.',
    falsePositiveGuidance: 'The resource may be intentionally shared or public, or ownership may be enforced elsewhere in the request pipeline.',
  },
  inconsistent_authorization: {
    id: 'CS-ACCESS-005',
    title: 'Inconsistent authorization across methods on the same resource',
    category: 'authorization',
    severity: 'medium',
    confidence: 'medium',
    candidateType: 'inconsistent_authorization',
    description:
      'One HTTP method on this resource path has no detected protection while a sibling method on the same path is role-, permission-, or ownership-protected.',
    remediation: 'Apply consistent authentication/authorization requirements across all methods that operate on the same resource.',
    falsePositiveGuidance: 'Methods may be legitimately asymmetric by design (e.g. GET public, DELETE protected); review each case.',
  },
};

function findingId(candidateType: FindingCandidateType, entry: AccessControlEntry, extra: string): string {
  const rule = ACCESS_RULES[candidateType];
  const basis = `${rule.id}:${entry.file}:${entry.line}:${entry.method}:${entry.path}:${extra}`;
  const suffix = createHash('sha256').update(basis).digest('hex').slice(0, 12);
  return `${rule.id}-${suffix}`;
}

function makeAccessFinding(
  candidateType: FindingCandidateType,
  entry: AccessControlEntry,
  explanation: string,
  evidence: SecurityEvidence[],
  confidence: Confidence
): AccessControlFinding {
  const rule = ACCESS_RULES[candidateType];
  return {
    id: findingId(candidateType, entry, explanation.slice(0, 40)),
    ruleId: rule.id,
    title: rule.title,
    category: rule.category,
    severity: rule.severity,
    confidence,
    status: 'suspected',
    file: entry.file,
    line: entry.line,
    evidence,
    description: rule.description,
    remediation: rule.remediation,
    verificationStatus: 'not_verified',
    routeId: entry.routeId,
    method: entry.method,
    path: entry.path,
    framework: entry.framework,
    sourceRange: entry.sourceRange,
    candidateType,
    explanation,
  };
}

function findMissingAuthentication(entry: AccessControlEntry): AccessControlFinding | null {
  if (entry.explicitlyPublic || !entry.pathResolved || entry.authentication.length > 0) return null;
  const sensitiveByResource = entry.stateChanging && entry.resourceParameters.length > 0;
  const sensitiveByAdmin = entry.administrative;
  if (!sensitiveByResource && !sensitiveByAdmin) return null;
  if (PUBLIC_PATH_HINT_RE.test(entry.path)) return null;
  const explanation = sensitiveByAdmin
    ? `Route ${entry.method} ${entry.path} appears administrative but no authentication control was found in the analyzed source.`
    : `Route ${entry.method} ${entry.path} changes state and operates on a specific resource (${entry.resourceParameters.join(', ')}) but no authentication control was found.`;
  const evidence: SecurityEvidence[] = [toSecurityEvidence(entry.file, entry.line, explanation)];
  return makeAccessFinding('missing_authentication', entry, explanation, evidence, weaker(entry.confidence, 'medium'));
}

function findMissingAuthorization(entry: AccessControlEntry): AccessControlFinding | null {
  if (!entry.pathResolved || entry.authentication.length === 0 || entry.authorization.length > 0) return null;
  if (!entry.administrative) return null;
  const explanation = `Route ${entry.method} ${entry.path} is authenticated but no role/permission/policy check was found, even though the route appears administrative.`;
  const evidence: SecurityEvidence[] = [
    ...entry.authentication.slice(0, 1).map((a) => toSecurityEvidence(a.file, a.line, `Authentication control: ${a.name}`)),
    toSecurityEvidence(entry.file, entry.line, explanation),
  ];
  return makeAccessFinding('missing_authorization', entry, explanation, evidence, weaker(entry.confidence, 'medium'));
}

function findIdorCandidates(entry: AccessControlEntry): AccessControlFinding[] {
  if (entry.authentication.length === 0 || entry.resourceParameters.length === 0 || entry.ownership.length > 0) return [];
  const findings: AccessControlFinding[] = [];
  const writeOrDelete = entry.resourceLoads.filter((l) => l.operation === 'write' || l.operation === 'delete');
  const reads = entry.resourceLoads.filter((l) => l.operation === 'read');
  if (writeOrDelete.length > 0) {
    const load = writeOrDelete[0]!;
    const explanation = `Route ${entry.method} ${entry.path} loads a resource by "${load.parameter}" and then ${load.operation}s it without a visible ownership/tenant comparison against the authenticated identity.`;
    const evidence: SecurityEvidence[] = [
      toSecurityEvidence(load.file, load.line, `Resource load: ${load.expression}`),
      toSecurityEvidence(entry.file, entry.line, explanation),
    ];
    findings.push(makeAccessFinding('idor_candidate', entry, explanation, evidence, weaker(entry.confidence, 'medium')));
  } else if (reads.length > 0) {
    const load = reads[0]!;
    const explanation = `Route ${entry.method} ${entry.path} reads a resource by "${load.parameter}" without a visible ownership/tenant comparison against the authenticated identity.`;
    const evidence: SecurityEvidence[] = [
      toSecurityEvidence(load.file, load.line, `Resource load: ${load.expression}`),
      toSecurityEvidence(entry.file, entry.line, explanation),
    ];
    findings.push(makeAccessFinding('user_resource_access', entry, explanation, evidence, weaker(entry.confidence, 'low')));
  }
  return findings;
}

function findInconsistentAuthorization(entries: readonly AccessControlEntry[]): AccessControlFinding[] {
  const groups = new Map<string, AccessControlEntry[]>();
  for (const entry of entries) {
    if (!entry.pathResolved) continue;
    const key = `${entry.file}::${normalizeResourcePath(entry.path)}`;
    const list = groups.get(key) ?? [];
    list.push(entry);
    groups.set(key, list);
  }
  const protectedStates = new Set<AccessState>(['role_protected', 'permission_protected', 'ownership_protected']);
  const findings: AccessControlFinding[] = [];
  for (const group of groups.values()) {
    if (group.length < 2) continue;
    const protectedEntries = group.filter((e) => protectedStates.has(e.state));
    const publicEntries = group.filter((e) => e.state === 'public');
    if (protectedEntries.length === 0 || publicEntries.length === 0) continue;
    for (const entry of publicEntries) {
      const sibling = protectedEntries[0]!;
      const explanation = `Route ${entry.method} ${entry.path} has no detected protection, while sibling method ${sibling.method} ${sibling.path} on the same resource is ${sibling.state} (${sibling.file}:${sibling.line}).`;
      const evidence: SecurityEvidence[] = [
        toSecurityEvidence(entry.file, entry.line, `Unprotected method: ${entry.method}`),
        toSecurityEvidence(sibling.file, sibling.line, `Protected sibling method: ${sibling.method}`),
      ];
      findings.push(makeAccessFinding('inconsistent_authorization', entry, explanation, evidence, weaker(entry.confidence, 'medium')));
    }
  }
  return findings;
}

function summarize(matrix: readonly AccessControlEntry[], findings: readonly AccessControlFinding[]): AccessControlSummary {
  const byState: Record<AccessState, number> = {
    public: 0,
    authenticated: 0,
    role_protected: 0,
    permission_protected: 0,
    ownership_protected: 0,
    mixed: 0,
    unknown: 0,
  };
  for (const e of matrix) byState[e.state] += 1;
  const findingsBySeverity: Record<SecuritySeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const findingsByRule: Record<string, number> = {};
  for (const f of findings) {
    findingsBySeverity[f.severity] += 1;
    findingsByRule[f.ruleId] = (findingsByRule[f.ruleId] ?? 0) + 1;
  }
  return {
    totalRoutes: matrix.length,
    byState,
    totalFindings: findings.length,
    findingsBySeverity,
    findingsByRule,
  };
}

export function analyzeAccessControl(config: AppConfig, entries: readonly AttackSurfaceEntry[]): AnalyzeAccessControlResult {
  const warnings: string[] = [];
  const profile = runProjectDiscovery(config.projectRoot);
  warnings.push(...profile.warnings);
  const ctx = createAdapterContext(config, profile, warnings);
  const resolver = createSourceResolver(ctx);
  const globals = collectGlobalGuards(resolver);
  const shared = createControlShared(resolver, globals);

  const matrix: AccessControlEntry[] = [];
  const frameworksSeen = new Set<RouteFramework>();

  for (const entry of entries) {
    frameworksSeen.add(entry.framework);

    let source: ReturnType<typeof resolver.forEntry>;
    try {
      source = resolver.forEntry(entry);
    } catch (e) {
      warnings.push(`Access-control analysis failed to load source for ${entry.method} ${entry.path} (${entry.file}:${entry.line}): ${(e as Error).message}`);
      source = { python: entry.language === 'python', parts: [], handlerResolved: false };
    }
    const resolved = source.parts.length > 0;

    let identities: IdentitySource[] = [];
    let controls: ReturnType<typeof collectEntryControls> = { authentication: [], authorization: [], publicMarkers: [] };
    let ownership: ReturnType<typeof analyzeOwnership> = { resourceParameters: [], loads: [], checks: [] };
    try {
      identities = collectIdentitySources(entry, source);
      controls = collectEntryControls(entry, source, identities, shared);
      ownership = analyzeOwnership(entry, source, identities);
    } catch (e) {
      warnings.push(`Access-control analysis failed for ${entry.method} ${entry.path} (${entry.file}:${entry.line}): ${(e as Error).message}`);
    }

    const explicitlyPublic = controls.publicMarkers.length > 0;
    const administrative = isAdministrative(entry.path, controls.authorization);
    const stateChanging = STATE_CHANGING.has(entry.method);
    const state = classifyState(explicitlyPublic, controls.authentication, controls.authorization, ownership.checks, resolved);
    const confidence = resolved ? entryConfidence(entry.confidence, controls.authentication, controls.authorization) : 'low';

    const evidence: Evidence[] = [...entry.evidence];
    if (!resolved) {
      evidence.push({
        source: `${entry.file}:${entry.line}`,
        detail: 'Source for this route could not be resolved; classified as unknown rather than guessed.',
      });
    }

    matrix.push({
      routeId: entry.id,
      method: entry.method,
      path: entry.path,
      pathResolved: entry.pathResolved,
      framework: entry.framework,
      file: entry.file,
      line: entry.line,
      sourceRange: entry.sourceRange,
      state,
      explicitlyPublic,
      administrative,
      stateChanging,
      authentication: controls.authentication,
      authorization: controls.authorization,
      ownership: ownership.checks,
      identitySources: identities,
      resourceParameters: ownership.resourceParameters,
      resourceLoads: ownership.loads,
      confidence,
      evidence,
    });
  }

  const findings: AccessControlFinding[] = [];
  for (const entry of matrix) {
    const missingAuthn = findMissingAuthentication(entry);
    if (missingAuthn) findings.push(missingAuthn);
    const missingAuthz = findMissingAuthorization(entry);
    if (missingAuthz) findings.push(missingAuthz);
    findings.push(...findIdorCandidates(entry));
  }
  findings.push(...findInconsistentAuthorization(matrix));

  return {
    project: { name: profile.projectName, ecosystem: profile.ecosystem },
    frameworks: Array.from(frameworksSeen),
    summary: summarize(matrix, findings),
    matrix,
    findings,
    warnings: Array.from(new Set(warnings)),
  };
}
