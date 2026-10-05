import type { Confidence } from '../discovery/types.js';
import type { HttpMethod, RouteFramework } from '../routes/types.js';
import type { FindingCandidateType } from '../access/types.js';


export type VerificationStatus = 'not_run' | 'blocked' | 'inconclusive' | 'verified' | 'not_reproduced';

export type VerificationCaseType =
  | 'missing_authentication'
  | 'idor_bola'
  | 'missing_authorization'
  | 'ownership'
  | 'public_private_inconsistency'
  | 'method_authorization';

export interface RuntimeTarget {
  allowedOrigin: string;
  allowPrivateNetworkTarget?: boolean;
  maxRequestsPerCase?: number;
  requestTimeoutMs?: number;
  maxResponseBytes?: number;
  maxRedirects?: number;
  minRequestIntervalMs?: number;
  maxConcurrency?: number;
  allowDestructiveMethods?: boolean;
  vettedTestPaths?: string[];
}

export type TestSessionKind = 'unauthenticated' | 'authenticated';

export interface TestSession {
  id: string;
  kind: TestSessionKind;
  headers?: Record<string, string>;
}

export interface RuntimeRequest {
  method: HttpMethod;
  path: string;
  sessionId: string | null;
  headers?: Record<string, string>;
  body?: string;
}

export interface RuntimeResponse {
  status: number;
  headers: Record<string, string>;
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
  note: string;
}

export interface VerificationCase {
  id: string;
  type: VerificationCaseType;
  findingId: string;
  routeId: string;
  method: HttpMethod;
  path: string;
  framework: RouteFramework;
  objective: string;
  preconditions: string[];
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
  summary: string;
  evidence: VerificationEvidence[];
  requestsIssued: number;
  startedAt: string;
  finishedAt: string;
  blockedReason: string | null;
}
