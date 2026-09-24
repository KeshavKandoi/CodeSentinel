export const PROOF_CASE_TYPES = [
  'idor_bola', 'missing_authentication', 'missing_authorization', 'mass_assignment',
  'sql_injection', 'command_injection', 'ssrf', 'xss_reflected', 'open_redirect',
  'jwt_verification', 'session_cookie_flags', 'csrf', 'webhook_signature',
  'unrestricted_upload', 'path_traversal', 'insecure_deserialization',
  'weak_password_storage', 'permissive_cors', 'authorization_inconsistency',
] as const;
export type ProofCaseType = (typeof PROOF_CASE_TYPES)[number];
export type ProofStatus = 'verified' | 'not_reproduced' | 'inconclusive' | 'blocked';

export interface SecurityProofCase {
  id: string;
  type: ProofCaseType;
  findingId: string;
  prerequisites: string[];
  requestShape: { method: string; path: string; body: string | null; headers: string[] };
  vulnerableOracle: string;
  safeOracle: string;
  maxRequests: number;
  allowedMethods: string[];
  requiredFixtureData: string[];
  evidenceCaptured: string[];
  blockedStates: string[];
  inconclusiveStates: string[];
}

export interface SecurityReceipt {
  receiptId: string;
  findingId: string;
  proofCase: SecurityProofCase;
  status: ProofStatus;
  redactedRequest: { method: string; path: string; sessionId: string | null } | null;
  responseFacts: Array<{ status: number; bodySnippet: string; finalUrl: string }>;
  oracle: string;
  whyProven: string;
  sourceRefs: string[];
  evidenceRefs: string[];
  remediationRef: string | null;
  reVerification: { status: ProofStatus | null; receiptId: string | null };
  limitation: string | null;
}

export interface SecurityGraphNode { id: string; kind: string; label: string; sourceRef: string; }
export interface SecurityGraphEdge { id: string; from: string; to: string; relation: string; confidence: 'high' | 'medium' | 'low'; evidenceRefs: string[]; }
export interface SecurityGraph { nodes: SecurityGraphNode[]; edges: SecurityGraphEdge[]; limitations: string[]; }
