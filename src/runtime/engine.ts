import type { AppConfig } from '../config.js';
import { analyzeAccessControl } from '../access/engine.js';
import type { AccessControlFinding } from '../access/types.js';
import { discoverRoutes } from '../routes/engine.js';
import type { AttackSurfaceEntry } from '../routes/types.js';
import { buildIdorCase, runIdorCase } from './cases/idorBola.js';
import { buildMethodAuthorizationCase, runMethodAuthorizationCase } from './cases/methodAuthorization.js';
import { buildMissingAuthenticationCase, runMissingAuthenticationCase } from './cases/missingAuthentication.js';
import { buildMissingAuthorizationCase, runMissingAuthorizationCase } from './cases/missingAuthorization.js';
import { buildOwnershipCase, runOwnershipCase } from './cases/ownership.js';
import { buildPublicPrivateInconsistencyCase, runPublicPrivateInconsistencyCase } from './cases/publicPrivateInconsistency.js';
import { blockedResult } from './cases/common.js';
import { RuntimeClientState } from './httpClient.js';
import { buildSessionMap, missingSessions } from './session.js';
import { validateTarget } from './targetGuard.js';
import type { RuntimeTarget, TestSession, VerificationCase, VerificationResult } from './types.js';

/**
 * Phase 6 orchestration: locates the static finding and its route (by
 * re-running the existing Phase 4/5 static engines -- this server holds no
 * persistent finding store), validates the target-authorization boundary,
 * selects the single applicable verification case for that finding's
 * candidateType, and executes only that case's minimum required requests.
 * Never verifies every finding automatically -- one findingId, one target,
 * one explicit call.
 */

export interface SessionParams {
  ownerSessionId?: string;
  otherSessionId?: string;
  lowPrivilegedSessionId?: string;
  authenticatedSessionId?: string;
}

export interface VerifyFindingRequest {
  findingId: string;
  target: RuntimeTarget;
  sessions?: TestSession[];
  sessionParams?: SessionParams;
}

export interface VerifyFindingOutcome {
  ok: true;
  data: {
    verificationCase: VerificationCase;
    result: VerificationResult;
    finding: AccessControlFinding & { runtimeVerification: VerificationResult };
  };
}

export interface VerifyFindingError {
  ok: false;
  error: { code: 'NOT_FOUND' | 'INVALID_INPUT' | 'TARGET_BLOCKED' | 'UNSUPPORTED_CANDIDATE_TYPE'; message: string };
}

export type VerifyFindingResult = VerifyFindingOutcome | VerifyFindingError;

interface AnalyzedProject {
  entries: AttackSurfaceEntry[];
  findings: AccessControlFinding[];
}

function runStaticAnalysis(config: AppConfig): AnalyzedProject {
  const routesOutcome = discoverRoutes(config);
  const entries = routesOutcome.ok ? routesOutcome.data.entries : [];
  const accessResult = analyzeAccessControl(config, entries);
  return { entries, findings: accessResult.findings };
}

/** Discovery-only preview: for every currently verifiable finding, what
 * case would run and what test inputs it requires. Never executes a
 * request -- purely informational, for an AI client deciding what to ask
 * the operator for before calling verify_finding. */
export function listVerificationCases(config: AppConfig): VerificationCase[] {
  const { entries, findings } = runStaticAnalysis(config);
  const cases: VerificationCase[] = [];
  for (const finding of findings) {
    const entry = entries.find((e) => e.id === finding.routeId);
    if (!entry) continue;
    const built = buildCaseForCandidate(finding, entry, {});
    if (built) cases.push(built.vcase);
  }
  return cases;
}

function buildCaseForCandidate(
  finding: AccessControlFinding,
  entry: AttackSurfaceEntry,
  params: SessionParams
): { vcase: VerificationCase; requiredParams: (keyof SessionParams)[] } | null {
  switch (finding.candidateType) {
    case 'missing_authentication':
      if (params.authenticatedSessionId) {
        return {
          vcase: buildPublicPrivateInconsistencyCase(finding, entry, params.authenticatedSessionId),
          requiredParams: ['authenticatedSessionId'],
        };
      }
      return { vcase: buildMissingAuthenticationCase(finding, entry), requiredParams: [] };
    case 'missing_authorization':
      return {
        vcase: buildMissingAuthorizationCase(finding, entry, params.lowPrivilegedSessionId ?? 'lowPrivileged'),
        requiredParams: ['lowPrivilegedSessionId'],
      };
    case 'idor_candidate':
      return {
        vcase: buildIdorCase(finding, entry, params.ownerSessionId ?? 'userA', params.otherSessionId ?? 'userB'),
        requiredParams: ['ownerSessionId', 'otherSessionId'],
      };
    case 'user_resource_access':
      return {
        vcase: buildOwnershipCase(finding, entry, params.ownerSessionId ?? 'userA', params.otherSessionId ?? 'userB'),
        requiredParams: ['ownerSessionId', 'otherSessionId'],
      };
    case 'inconsistent_authorization':
      return { vcase: buildMethodAuthorizationCase(finding, entry), requiredParams: [] };
    default:
      return null;
  }
}

export async function verifyFinding(config: AppConfig, request: VerifyFindingRequest): Promise<VerifyFindingResult> {
  const { entries, findings } = runStaticAnalysis(config);
  const finding = findings.find((f) => f.id === request.findingId);
  if (!finding) {
    return { ok: false, error: { code: 'NOT_FOUND', message: `No verifiable static finding with id "${request.findingId}" was found. Findings are recomputed on each call; re-run analyze_access_control to get current ids.` } };
  }
  const entry = entries.find((e) => e.id === finding.routeId);
  if (!entry) {
    return { ok: false, error: { code: 'NOT_FOUND', message: `Finding "${request.findingId}" references route "${finding.routeId}", which was not found in the current route inventory.` } };
  }

  const built = buildCaseForCandidate(finding, entry, request.sessionParams ?? {});
  if (!built) {
    return {
      ok: false,
      error: {
        code: 'UNSUPPORTED_CANDIDATE_TYPE',
        message: `Finding candidateType "${finding.candidateType}" has no runtime verification case implemented.`,
      },
    };
  }
  const { vcase, requiredParams } = built;
  const startedAt = new Date().toISOString();

  const missingParams = requiredParams.filter((p) => !request.sessionParams?.[p]);
  if (missingParams.length > 0) {
    const result = blockedResult(vcase, `Missing required sessionParams: ${missingParams.join(', ')}.`, startedAt);
    return { ok: true, data: { verificationCase: vcase, result, finding: attachVerification(finding, result) } };
  }

  const targetBlock = await validateTarget(request.target);
  if (targetBlock) {
    const result = blockedResult(vcase, targetBlock.reason, startedAt);
    return { ok: true, data: { verificationCase: vcase, result, finding: attachVerification(finding, result) } };
  }

  const sessions = buildSessionMap(request.sessions ?? []);
  const missing = missingSessions(sessions, vcase.requiredSessions);
  if (missing.length > 0) {
    const result = blockedResult(vcase, `Missing required test sessions: ${missing.join(', ')}.`, startedAt);
    return { ok: true, data: { verificationCase: vcase, result, finding: attachVerification(finding, result) } };
  }

  const state = new RuntimeClientState(request.target);
  const result = await executeCase(vcase, finding.candidateType, request, state);
  return { ok: true, data: { verificationCase: vcase, result, finding: attachVerification(finding, result) } };
}

async function executeCase(
  vcase: VerificationCase,
  candidateType: AccessControlFinding['candidateType'],
  request: VerifyFindingRequest,
  state: RuntimeClientState
): Promise<VerificationResult> {
  const sessions = buildSessionMap(request.sessions ?? []);
  const params = request.sessionParams ?? {};
  switch (candidateType) {
    case 'missing_authentication':
      if (params.authenticatedSessionId) {
        return runPublicPrivateInconsistencyCase(vcase, params.authenticatedSessionId, request.target, sessions, state);
      }
      return runMissingAuthenticationCase(vcase, request.target, sessions, state);
    case 'missing_authorization':
      return runMissingAuthorizationCase(vcase, params.lowPrivilegedSessionId!, request.target, sessions, state);
    case 'idor_candidate':
      return runIdorCase(vcase, params.otherSessionId!, request.target, sessions, state);
    case 'user_resource_access':
      return runOwnershipCase(vcase, params.otherSessionId!, request.target, sessions, state);
    case 'inconsistent_authorization':
      return runMethodAuthorizationCase(vcase, request.target, sessions, state);
    default:
      return blockedResult(vcase, `Unsupported candidateType "${candidateType}".`, new Date().toISOString());
  }
}

/**
 * Attaches runtime verification metadata to a *new* object. Static access
 * findings intentionally remain `status: 'suspected'`; runtime state belongs
 * in the separate verification metadata and verificationStatus fields.
 */
function attachVerification(
  finding: AccessControlFinding,
  result: VerificationResult
): AccessControlFinding & { runtimeVerification: VerificationResult } {
  return {
    ...finding,
    verificationStatus: result.status === 'verified' ? 'manually_verified' : finding.verificationStatus,
    runtimeVerification: result,
  };
}
