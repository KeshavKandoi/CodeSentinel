import type { AccessControlFinding } from '../../access/types.js';
import type { AttackSurfaceEntry } from '../../routes/types.js';
import { issueRuntimeRequest, RuntimeClientState } from '../httpClient.js';
import type { RuntimeTarget, TestSession, VerificationCase, VerificationResult } from '../types.js';
import { blockedResult, buildResult, hasUnresolvedSegment, isAuthRejection, isNotFound, isSuccessStatus } from './common.js';

/**
 * Case 2: IDOR/BOLA candidate.
 *
 * Uses two explicitly configured controlled test identities. `ownerSessionId`
 * is the identity the resource at `vcase.path` belongs to (used only for
 * context/objective text -- never called here); `otherSessionId` is the
 * identity that must NOT be able to access/modify it. The path must already
 * be a concrete, fixture-supplied resource identifier -- this case never
 * guesses or enumerates resource ids.
 *
 * A rejection (401/403/404) for the other identity is evidence ownership IS
 * enforced (not_reproduced). For a state-changing method, a 2xx response
 * directly demonstrates the cross-user write/delete succeeded -- that is the
 * verification condition itself, not an incidental 200, so it is reported
 * verified. For a read (GET/HEAD), a 2xx is only reported inconclusive: it
 * is consistent with IDOR but could equally be a legitimately shared/public
 * resource, and this engine has no way to compare response content against
 * "owner-only" data without risking exposing more than necessary.
 */

export function buildIdorCase(
  finding: AccessControlFinding,
  entry: AttackSurfaceEntry,
  ownerSessionId: string,
  otherSessionId: string
): VerificationCase {
  return {
    id: `VC-IDOR-${finding.id}`,
    type: 'idor_bola',
    findingId: finding.id,
    routeId: entry.id,
    method: entry.method,
    path: entry.path,
    framework: entry.framework,
    objective: `Determine whether identity "${otherSessionId}" can access/modify a resource at ${entry.method} ${entry.path} that belongs to identity "${ownerSessionId}".`,
    preconditions: [
      'The route path must reference a concrete, fixture-supplied resource id belonging to ownerSessionId.',
      `Both "${ownerSessionId}" and "${otherSessionId}" must be configured test sessions.`,
    ],
    requiredSessions: [ownerSessionId, otherSessionId],
    expectedSecureBehavior: `Identity "${otherSessionId}" should be rejected (401/403) or the resource should not be found (404) for this identity.`,
    cleanupRequired: entry.method === 'DELETE',
    relatedCandidateType: 'idor_candidate',
  };
}

export async function runIdorCase(
  vcase: VerificationCase,
  otherSessionId: string,
  target: RuntimeTarget,
  sessions: Map<string, TestSession>,
  state: RuntimeClientState
): Promise<VerificationResult> {
  const startedAt = new Date().toISOString();

  if (hasUnresolvedSegment(vcase.path)) {
    return blockedResult(vcase, `Route path "${vcase.path}" still contains an unresolved dynamic segment.`, startedAt);
  }
  if (vcase.method === 'DELETE' && target.allowDestructiveMethods !== true) {
    return blockedResult(vcase, 'DELETE is a destructive method and allowDestructiveMethods is not enabled on the target.', startedAt);
  }

  const evidence = [
    await issueRuntimeRequest(target, sessions, { method: vcase.method, path: vcase.path, sessionId: otherSessionId }, state),
  ];
  const response = evidence[0]!.response;

  if (response.status === 0) {
    return blockedResult(vcase, evidence[0]!.note.replace(/^Blocked:\s*/, ''), startedAt, evidence);
  }

  if (isAuthRejection(response) || isNotFound(response)) {
    return buildResult(
      vcase,
      'not_reproduced',
      'high',
      `Identity "${otherSessionId}" received ${response.status} when accessing ${vcase.method} ${vcase.path}, indicating ownership is enforced. IDOR was not reproduced.`,
      evidence,
      startedAt
    );
  }

  const isWrite = vcase.method === 'POST' || vcase.method === 'PUT' || vcase.method === 'PATCH' || vcase.method === 'DELETE';
  if (isSuccessStatus(response) && isWrite) {
    return buildResult(
      vcase,
      'verified',
      'high',
      `Identity "${otherSessionId}" successfully performed ${vcase.method} ${vcase.path} (status ${response.status}) against a resource it does not own. This directly demonstrates the missing ownership check, not merely a generic 2xx.`,
      evidence,
      startedAt
    );
  }

  if (isSuccessStatus(response)) {
    return buildResult(
      vcase,
      'inconclusive',
      'medium',
      `Identity "${otherSessionId}" received ${response.status} reading ${vcase.method} ${vcase.path}. This is consistent with IDOR but a 2xx read alone does not prove the resource is owner-specific rather than legitimately shared, so this is reported inconclusive.`,
      evidence,
      startedAt
    );
  }

  return buildResult(
    vcase,
    'inconclusive',
    'low',
    `Identity "${otherSessionId}" received an unexpected status ${response.status}, which does not clearly indicate ownership enforcement or its absence.`,
    evidence,
    startedAt
  );
}
