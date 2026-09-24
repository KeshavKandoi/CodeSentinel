import type { AccessControlFinding } from '../../access/types.js';
import type { AttackSurfaceEntry } from '../../routes/types.js';
import { issueRuntimeRequest, RuntimeClientState } from '../httpClient.js';
import type { RuntimeTarget, TestSession, VerificationCase, VerificationResult } from '../types.js';
import { blockedResult, buildResult, hasUnresolvedSegment, isAuthRejection, isSuccessStatus } from './common.js';

const DESTRUCTIVE_METHODS = new Set(['DELETE']);

/**
 * Case 6: Method-level authorization inconsistency.
 *
 * Phase 5's `inconsistent_authorization` finding already identifies a
 * specific unprotected method sibling to a protected one on the same
 * resource. This case only ever tests that one already-identified weaker
 * method, and only with explicitly configured, non-destructive test calls.
 * DELETE (or any other method the caller marks destructive) is refused
 * unless the target explicitly sets allowDestructiveMethods AND the case
 * was built against a dedicated fixture endpoint the caller has vetted --
 * this module does not attempt to infer "non-destructive" on its own.
 */

export function buildMethodAuthorizationCase(finding: AccessControlFinding, entry: AttackSurfaceEntry): VerificationCase {
  return {
    id: `VC-METHOD-AUTHZ-${finding.id}`,
    type: 'method_authorization',
    findingId: finding.id,
    routeId: entry.id,
    method: entry.method,
    path: entry.path,
    framework: entry.framework,
    objective: `Determine whether ${entry.method} ${entry.path} -- flagged as the unprotected sibling method for this resource -- is actually reachable without the protection its sibling method has.`,
    preconditions: ['The route path must be fully concrete.', 'The method under test must not be destructive unless explicitly authorized.'],
    requiredSessions: [],
    expectedSecureBehavior: 'The route should require the same authentication/authorization as its sibling method.',
    cleanupRequired: false,
    relatedCandidateType: 'inconsistent_authorization',
  };
}

export async function runMethodAuthorizationCase(
  vcase: VerificationCase,
  target: RuntimeTarget,
  sessions: Map<string, TestSession>,
  state: RuntimeClientState
): Promise<VerificationResult> {
  const startedAt = new Date().toISOString();

  if (hasUnresolvedSegment(vcase.path)) {
    return blockedResult(vcase, `Route path "${vcase.path}" still contains an unresolved dynamic segment.`, startedAt);
  }
  if (DESTRUCTIVE_METHODS.has(vcase.method) && target.allowDestructiveMethods !== true) {
    return blockedResult(
      vcase,
      `${vcase.method} is a destructive method; refusing to test it unless the target explicitly enables allowDestructiveMethods against a vetted fixture endpoint.`,
      startedAt
    );
  }

  const evidence = [await issueRuntimeRequest(target, sessions, { method: vcase.method, path: vcase.path, sessionId: null }, state)];
  const response = evidence[0]!.response;

  if (response.status === 0) {
    return blockedResult(vcase, evidence[0]!.note.replace(/^Blocked:\s*/, ''), startedAt, evidence);
  }

  if (isAuthRejection(response)) {
    return buildResult(
      vcase,
      'not_reproduced',
      'high',
      `${vcase.method} ${vcase.path} received ${response.status}; the method is in fact protected. Inconsistency not reproduced at runtime.`,
      evidence,
      startedAt
    );
  }

  const isWrite = vcase.method === 'POST' || vcase.method === 'PUT' || vcase.method === 'PATCH' || vcase.method === 'DELETE';
  if (isSuccessStatus(response) && isWrite) {
    return buildResult(
      vcase,
      'verified',
      'medium',
      `${vcase.method} ${vcase.path} received ${response.status} with no authentication, confirming the unprotected state-changing method lacks the protection its sibling method has.`,
      evidence,
      startedAt
    );
  }

  if (isSuccessStatus(response)) {
    return buildResult(
      vcase,
      'inconclusive',
      'medium',
      `${vcase.method} ${vcase.path} received ${response.status}, but a successful read alone does not prove that the sibling method's protection was bypassed.`,
      evidence,
      startedAt
    );
  }

  return buildResult(vcase, 'inconclusive', 'low', `Received an unexpected status ${response.status}.`, evidence, startedAt);
}
