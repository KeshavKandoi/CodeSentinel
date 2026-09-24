import type { Confidence } from '../discovery/types.js';
import type { HttpMethod, RouteFramework } from '../routes/types.js';
import type { FindingCandidateType } from '../access/types.js';

/**
 * Phase 6: Controlled Runtime Security Verification.
 *
 * This subsystem is deliberately separate from src/security (Phase 3 static
 * scanner) and src/routes (Phase 4 static route discovery). It never runs
 * unless given an explicit RuntimeTarget with an allowlisted origin, and it
 * only ever proves or disproves a specific, narrowly-scoped hypothesis tied
 * to one existing static finding -- it never scans, crawls, brute-forces,
 * or exploits beyond the minimum requests required for that one hypothesis.
 */

export type VerificationStatus = 'not_run' | 'blocked' | 'inconclusive' | 'verified' | 'not_reproduced';

export type VerificationCaseType =
  | 'missing_authentication'
  | 'idor_bola'
  | 'missing_authorization'
  | 'ownership'
  | 'public_private_inconsistency'
  | 'method_authorization';

/**
 * The single source of truth for what runtime testing is allowed to touch.
 * Constructed only from explicit configuration passed into verify_finding --
 * never inferred, never defaulted to "localhost is always safe" when a
 * target was supplied externally.
 */
export interface RuntimeTarget {
  /** Exact allowed origin, e.g. "http://127.0.0.1:3000" or an explicitly
   * configured staging origin. Scheme + host + port; no path. */
  allowedOrigin: string;
  /** Explicit opt-in required to allow a private/loopback destination to be
   * used as the authorized target. Without this, private-range origins are
   * rejected even if they match allowedOrigin, closing the "attacker sets
   * allowedOrigin to a private target" loophole for staging-style configs
   * that are NOT localhost. Loopback origins (127.0.0.1/localhost) are
   * always allowed since they are the default, expected local-dev target. */
  allowPrivateNetworkTarget?: boolean;
  /** Hard ceiling on requests any single VerificationCase may issue. */
  maxRequestsPerCase?: number;
  /** Per-request timeout in ms. */
  requestTimeoutMs?: number;
  /** Max response body bytes read before aborting. */
  maxResponseBytes?: number;
  /** Max redirects followed; every hop must still resolve inside allowedOrigin. */
  maxRedirects?: number;
  /** Minimum ms between requests issued by the client (simple rate limit). */
  minRequestIntervalMs?: number;
  /** Max concurrent in-flight requests. */
  maxConcurrency?: number;
  /** Must be explicitly set true to allow a verification case to issue a
   * DELETE (or other destructive) request, and even then only against a
   * route the fixture/target explicitly marks as a safe, non-destructive
   * test endpoint. Defaults to false: destructive methods are blocked. */
  allowDestructiveMethods?: boolean;
}

export type TestSessionKind = 'unauthenticated' | 'authenticated';

/**
 * A controlled test identity. Credentials come only from this explicit,
 * caller-supplied configuration -- never read automatically from .env files
 * or other project source. Designed so a later phase can supply two
 * identities (e.g. userA / userB) for ownership/IDOR verification without
 * changing this shape.
 */
export interface TestSession {
  id: string; // caller-chosen label, e.g. "userA", "admin", "anonymous"
  kind: TestSessionKind;
  /** Raw header values to attach verbatim, e.g. { Authorization: "Bearer ..." }.
   * Never logged/echoed in evidence -- always redacted. */
  headers?: Record<string, string>;
}

export interface RuntimeRequest {
  method: HttpMethod;
  /** Path relative to the target origin, e.g. "/documents/42". */
  path: string;
  sessionId: string | null; // references a TestSession.id, or null for no auth
  headers?: Record<string, string>;
  body?: string;
}

export interface RuntimeResponse {
  status: number;
  /** Redacted headers -- sensitive header values are never retained. */
  headers: Record<string, string>;
  /** Truncated, size-capped body. May be redacted/omitted for sensitive content. */
  bodySnippet: string;
  bodyTruncated: boolean;
  durationMs: number;
  redirected: boolean;
  finalUrl: string;
}

export interface VerificationEvidence {
  request: {
    method: HttpMethod;
    path: string;
    sessionId: string | null;
  };
  response: RuntimeResponse;
  /** Deterministic, code-evaluated explanation of what this evidence shows
   * with respect to the verification condition. Never an LLM judgment. */
  note: string;
}

/**
 * One narrowly-scoped runtime hypothesis, derived from exactly one existing
 * static finding (SecurityFinding / AccessControlFinding) and/or
 * AttackSurfaceEntry. Verification conditions are deterministic code, never
 * an LLM decision.
 */
export interface VerificationCase {
  id: string;
  type: VerificationCaseType;
  /** The static finding this case exists to verify. */
  findingId: string;
  /** The route this case exercises. */
  routeId: string;
  method: HttpMethod;
  path: string;
  framework: RouteFramework;
  objective: string;
  preconditions: string[];
  /** Session ids this case requires to exist in the target-session config
   * before it can run (e.g. ["userA", "userB"]). */
  requiredSessions: string[];
  expectedSecureBehavior: string;
  cleanupRequired: boolean;
  relatedCandidateType: FindingCandidateType | null;
}

export interface VerificationResult {
  caseId: string;
  caseType: VerificationCaseType;
  findingId: string;
  routeId: string;
  status: VerificationStatus;
  confidence: Confidence;
  /** Human-readable, deterministic summary of why this status was reached. */
  summary: string;
  evidence: VerificationEvidence[];
  requestsIssued: number;
  startedAt: string;
  finishedAt: string;
  /** Populated when status is 'blocked' -- explains what boundary stopped it. */
  blockedReason: string | null;
}
