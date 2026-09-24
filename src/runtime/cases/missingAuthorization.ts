import type { AccessControlFinding } from '../../access/types.js';
import type { AttackSurfaceEntry } from '../../routes/types.js';
import { issueRuntimeRequest, RuntimeClientState } from '../httpClient.js';
import type { RuntimeTarget, TestSession, VerificationCase, VerificationResult } from '../types.js';
import { blockedResult, buildResult, hasUnresolvedSegment, isAuthRejection, isSuccessStatus } from './common.js';

/**
 * Case 3: Missing authorization candidate.
 *
 * Uses an explicitly configured lower-privileged identity and requests a
 * route Phase 5 flagged as administrative/privileged. A rejection is
 * evidence the role check IS enforced (not_reproduced). For a
 * state-changing method, a 2xx response directly demonstrates the
 * privileged action succeeded for a low-privileged identity -- the
 * verification condition itself. For a read, 2xx is inconclusive for the
 * same reason as the other cases: a generic response body is not proof the
 * privileged action/resource was actually returned.
 */

export function buildMissingAuthorizationCase(
  finding: AccessControlFinding,
  entry: AttackSurfaceEntry,
  lowPrivilegedSessionId: string
): VerificationCase {
  return {
    id: `VC-MISSING-AUTHZ-${finding.id}`,
    type: 'missing_authorization',
    findingId: finding.id,
    routeId: entry.id,
    method: entry.method,
    path: entry.path,
    framework: entry.framework,
    objective: `Determine whether a lower-privileged identity ("${lowPrivilegedSessionId}") can perform ${entry.method} ${entry.path}, an action Phase 5 flagged as requiring elevated privilege.`,
    preconditions: [`"${lowPrivilegedSessionId}" must be a configured, authenticated test session with no elevated role/permission.`],
    requiredSessions: [lowPrivilegedSessionId],
    expectedSecureBehavior: `The route should reject "${lowPrivilegedSessionId}" with 401 or 403.`,
    cleanupRequired: entry.method === 'DELETE' || entry.method === 'PUT' || entry.method === 'PATCH' || entry.method === 'POST',
    relatedCandidateType: 'missing_authorization',
  };
}

export async function runMissingAuthorizationCase(
  vcase: VerificationCase,
  lowPrivilegedSessionId: string,
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
    await issueRuntimeRequest(target, sessions, { method: vcase.method, path: vcase.path, sessionId: lowPrivilegedSessionId }, state),
  ];
  const response = evidence[0]!.response;

  if (response.status === 0) {
    return blockedResult(vcase, evidence[0]!.note.replace(/^Blocked:\s*/, ''), startedAt, evidence);
  }

  if (isAuthRejection(response)) {
    return buildResult(
      vcase,
      'not_reproduced',
      'high',
      `Lower-privileged identity "${lowPrivilegedSessionId}" received ${response.status} performing ${vcase.method} ${vcase.path}. Authorization is enforced; missing-authorization was not reproduced.`,
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
      `Lower-privileged identity "${lowPrivilegedSessionId}" successfully performed the privileged action ${vcase.method} ${vcase.path} (status ${response.status}). This directly demonstrates missing role/permission enforcement.`,
      evidence,
      startedAt
    );
  }

  if (isSuccessStatus(response)) {
    return buildResult(
      vcase,
      'inconclusive',
      'medium',
      `Lower-privileged identity "${lowPrivilegedSessionId}" received ${response.status} reading ${vcase.method} ${vcase.path}. Consistent with missing authorization but not conclusive on its own for a read.`,
      evidence,
      startedAt
    );
  }

  return buildResult(
    vcase,
    'inconclusive',
    'low',
    `Received an unexpected status ${response.status}, which does not clearly indicate enforcement or its absence.`,
    evidence,
    startedAt
  );
}
