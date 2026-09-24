import type { AccessControlFinding } from '../../access/types.js';
import type { AttackSurfaceEntry } from '../../routes/types.js';
import { issueRuntimeRequest, RuntimeClientState } from '../httpClient.js';
import type { RuntimeTarget, TestSession, VerificationCase, VerificationResult } from '../types.js';
import { blockedResult, buildResult, hasUnresolvedSegment, isAuthRejection, isSuccessStatus } from './common.js';

/**
 * Case 1: Missing authentication candidate.
 *
 * Requests the route without authentication and compares against the
 * expected protected behavior. A 401/403 is treated as evidence the route
 * IS protected (not_reproduced). A 2xx response is *consistent* with
 * missing authentication but is never enough on its own to mark the finding
 * verified -- a generic public page returning 200 is not proof of an
 * authorization bypass -- so a bare success status is reported
 * `inconclusive`, per the spec's explicit "never prove a vulnerability
 * merely by receiving HTTP 200" requirement.
 */

export function buildMissingAuthenticationCase(finding: AccessControlFinding, entry: AttackSurfaceEntry): VerificationCase {
  return {
    id: `VC-MISSING-AUTHN-${finding.id}`,
    type: 'missing_authentication',
    findingId: finding.id,
    routeId: entry.id,
    method: entry.method,
    path: entry.path,
    framework: entry.framework,
    objective: `Determine whether ${entry.method} ${entry.path} is reachable without authentication.`,
    preconditions: ['The route path must be fully concrete -- no unresolved dynamic segments.'],
    requiredSessions: [],
    expectedSecureBehavior: 'The route should reject an unauthenticated request with 401 or 403.',
    cleanupRequired: false,
    relatedCandidateType: 'missing_authentication',
  };
}

export async function runMissingAuthenticationCase(
  vcase: VerificationCase,
  target: RuntimeTarget,
  sessions: Map<string, TestSession>,
  state: RuntimeClientState
): Promise<VerificationResult> {
  const startedAt = new Date().toISOString();

  if (hasUnresolvedSegment(vcase.path)) {
    return blockedResult(
      vcase,
      `Route path "${vcase.path}" still contains an unresolved dynamic segment; supply a concrete path before verifying.`,
      startedAt
    );
  }

  const method = vcase.method === 'ALL' || vcase.method === 'unknown' ? 'GET' : vcase.method;
  const evidence = [await issueRuntimeRequest(target, sessions, { method, path: vcase.path, sessionId: null }, state)];
  const response = evidence[0]!.response;

  if (response.status === 0) {
    return blockedResult(vcase, evidence[0]!.note.replace(/^Blocked:\s*/, ''), startedAt, evidence);
  }

  if (isAuthRejection(response)) {
    return buildResult(
      vcase,
      'not_reproduced',
      'high',
      `Unauthenticated request to ${method} ${vcase.path} received ${response.status}, indicating the route is protected. The missing-authentication finding was not reproduced.`,
      evidence,
      startedAt
    );
  }

  if (isSuccessStatus(response)) {
    return buildResult(
      vcase,
      'inconclusive',
      'medium',
      `Unauthenticated request to ${method} ${vcase.path} received ${response.status}. This is consistent with missing authentication, but a 2xx status alone does not prove the actual protected resource was returned rather than a generic public page, so this is reported inconclusive rather than verified.`,
      evidence,
      startedAt
    );
  }

  return buildResult(
    vcase,
    'inconclusive',
    'low',
    `Unauthenticated request to ${method} ${vcase.path} received an unexpected status ${response.status}, which does not clearly indicate either protection or exposure.`,
    evidence,
    startedAt
  );
}
