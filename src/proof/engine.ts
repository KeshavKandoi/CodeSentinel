import crypto from 'node:crypto';
import type { AppConfig } from '../config.js';
import { analyzeAccessControl } from '../access/engine.js';
import { discoverRoutes } from '../routes/engine.js';
import { runProjectDiscovery } from '../discovery/projectDiscovery.js';
import { listFiles } from '../fs/fsOperations.js';
import { verifyFinding } from '../runtime/engine.js';
import type { VerifyFindingRequest } from '../runtime/engine.js';
import { issueRuntimeRequest, RuntimeClientState } from '../runtime/httpClient.js';
import { buildResult, blockedResult, hasUnresolvedSegment } from '../runtime/cases/common.js';
import { buildSessionMap } from '../runtime/session.js';
import type { RuntimeTarget, VerificationEvidence, VerificationResult } from '../runtime/types.js';
import { scanProject } from '../security/scanner.js';
import type { SecurityFinding } from '../security/types.js';
import type { AttackSurfaceEntry } from '../routes/types.js';
import { detachedRedacted } from '../report/redaction.js';
import { err, ok, type ToolOutcome } from '../types.js';
import type { ProofCaseType, ProofReplayContract, SecurityGraph, SecurityGraphEdge, SecurityGraphNode, SecurityProofCase, SecurityReceipt } from './types.js';
import { PROOF_CASE_TYPES } from './types.js';

const hash = (value: string): string => crypto.createHash('sha256').update(value).digest('hex').slice(0, 24);
const receipts = new Map<string, import('./types.js').SecurityReceipt>();
function storeReceipt(receipt: SecurityReceipt): SecurityReceipt {
  const stored = detachedRedacted(receipt);
  receipts.set(stored.receiptId, stored);
  return detachedRedacted(stored);
}
export interface SecurityProofAdapter {
  type: ProofCaseType;
  candidateTypes: string[];
  buildCase(findingId: string, method: string, path: string): SecurityProofCase;
  execute(config: AppConfig, request: VerifyFindingRequest): ReturnType<typeof verifyFinding>;
}

interface SourceProofAdapter {
  type: ProofCaseType;
  categories: string[];
  marker: string;
  requestValue?: string;
  parameter: string;
  title: string;
  notes: string;
  method?: 'GET' | 'POST';
  requestBody?: string;
  requestHeaders?: Record<string, string>;
  sessionLabelReferences?: string[];
  oracleKind?: 'body_contains' | 'location_contains' | 'header_contains' | 'cookie_flags_incomplete';
  matchesFinding?: (finding: SecurityFinding) => boolean;
}

const metadata = (type: ProofCaseType, findingId: string, method = 'GET', path = '/', executable = false, adapterNotes = 'No executable adapter is registered for this proof class.'): SecurityProofCase => ({
  id: `proof-case-${hash(`${type}|${findingId}`)}`, type, findingId,
  prerequisites: ['An evidence-backed static candidate or route relation exists.', 'The operator supplies an explicitly authorized target when execution is requested.'],
  requestShape: { method, path, body: null, headers: [] },
  vulnerableOracle: type === 'idor_bola' ? 'A non-owner identity successfully performs a state-changing or semantically owner-specific operation.' : type === 'missing_authentication' ? 'An unauthenticated request reaches a protected resource with deterministic semantic evidence.' : type === 'missing_authorization' || type === 'authorization_inconsistency' ? 'A lower-privilege identity successfully performs the protected state-changing operation.' : 'A deterministic response/body oracle demonstrates the security property failure; status alone is insufficient.',
  safeOracle: 'An authentication/authorization rejection or an explicit safe semantic response demonstrates the control, subject to the case-specific evidence.',
  maxRequests: type === 'idor_bola' ? 2 : 1,
  allowedMethods: type === 'idor_bola' || type === 'missing_authorization' ? ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] : ['GET', 'HEAD', 'OPTIONS'],
  requiredFixtureData: ['A disposable local fixture with known routes and deterministic expected behavior.'],
  evidenceCaptured: ['Bounded request metadata', 'Redacted response facts', 'Deterministic oracle result', 'Source and route references'],
  blockedStates: ['Target rejected by Phase 6 target guard', 'Missing concrete route/session', 'Unsupported candidate type', 'Request or budget safety limit'],
  inconclusiveStates: ['Generic success without semantic proof', 'Static signal lacks an executable proof case', 'Ambiguous or incomplete fixture behavior'],
  executable,
  adapterNotes,
});

const EXECUTABLE_ADAPTERS: SecurityProofAdapter[] = [
  { type: 'idor_bola', candidateTypes: ['idor_candidate', 'user_resource_access'], buildCase: (id, method, path) => metadata('idor_bola', id, method, path, true, 'Delegates to the existing Phase 6 ownership proof.'), execute: (config, request) => verifyFinding(config, request) },
  { type: 'missing_authentication', candidateTypes: ['missing_authentication'], buildCase: (id, method, path) => metadata('missing_authentication', id, method, path, true, 'Delegates to the existing Phase 6 authentication proof.'), execute: (config, request) => verifyFinding(config, request) },
  { type: 'missing_authorization', candidateTypes: ['missing_authorization'], buildCase: (id, method, path) => metadata('missing_authorization', id, method, path, true, 'Delegates to the existing Phase 6 authorization proof.'), execute: (config, request) => verifyFinding(config, request) },
  { type: 'authorization_inconsistency', candidateTypes: ['inconsistent_authorization'], buildCase: (id, method, path) => metadata('authorization_inconsistency', id, method, path, true, 'Delegates to the existing Phase 6 cross-method proof.'), execute: (config, request) => verifyFinding(config, request) },
];

const SAFE_SOURCE_ADAPTERS: SourceProofAdapter[] = [
  { type: 'path_traversal', categories: ['path_traversal'], marker: 'CODESENTINEL_PROOF_OUTSIDE_ROOT', parameter: 'path', title: 'Path traversal proof', notes: 'Requires a local fixture to return the exact outside-root marker only when traversal succeeds.' },
  { type: 'open_redirect', categories: ['open_redirect', 'insecure_redirects'], marker: 'https://codesentinel.invalid/proof', requestValue: 'codesentinel-proof-redirect', parameter: 'url', title: 'Open redirect proof', notes: 'Uses a harmless local probe token; a fixture-controlled Location header provides the non-routable oracle and is never followed.' },
  { type: 'ssrf', categories: ['ssrf'], marker: 'CODESENTINEL_PROOF_SSRF_SENTINEL', parameter: 'url', title: 'SSRF proof', notes: 'Requires a local fixture-controlled SSRF oracle; no external or metadata target is used.' },
  { type: 'sql_injection', categories: ['injection'], marker: 'CODESENTINEL_PROOF_SQLI_SENTINEL', parameter: 'query', title: 'SQL injection proof', notes: 'Requires a local fixture-controlled semantic marker, never a generic SQL error.' },
  { type: 'command_injection', categories: ['command_injection'], marker: 'CODESENTINEL_PROOF_COMMAND_SENTINEL', parameter: 'command', title: 'Command injection proof', notes: 'Requires a local fixture-controlled marker; CodeSentinel never executes the supplied value.' },
  { type: 'xss_reflected', categories: ['xss'], marker: 'CODESENTINEL_PROOF_XSS_SENTINEL', parameter: 'q', title: 'Reflected XSS proof', notes: 'Verifies exact unencoded reflection of a unique inert marker, not script execution.' },
  { type: 'jwt_verification', categories: ['authentication'], marker: 'CODESENTINEL_PROOF_JWT_ACCEPTED', requestValue: 'codesentinel-invalid-jwt', parameter: 'token', title: 'JWT verification proof', notes: 'Uses a deterministic invalid token and only accepts an explicit fixture oracle; it never treats a generic 2xx as proof.', matchesFinding: (finding) => finding.ruleId === 'CS-NODE-016' },
  { type: 'session_cookie_flags', categories: ['security_configuration'], marker: 'httponly,samesite,secure', parameter: 'probe', title: 'Session cookie flags proof', notes: 'Inspects only a redacted cookie-attribute summary; cookie names and values are never retained.', oracleKind: 'cookie_flags_incomplete', matchesFinding: (finding) => finding.ruleId === 'CS-NODE-017' },
  { type: 'permissive_cors', categories: ['cors'], marker: 'access-control-allow-origin:*', parameter: 'origin', title: 'Permissive CORS proof', notes: 'Requires the actual response header to allow every origin; status alone is insufficient.', oracleKind: 'header_contains' },
  { type: 'insecure_deserialization', categories: ['deserialization'], marker: 'CODESENTINEL_PROOF_DESERIALIZED', parameter: 'payload', title: 'Insecure deserialization proof', notes: 'Requires an explicit local semantic marker and never executes the supplied payload in CodeSentinel.', matchesFinding: (finding) => finding.ruleId === 'CS-NODE-011' },
  { type: 'csrf', categories: ['csrf'], marker: 'CODESENTINEL_PROOF_CSRF_ACCEPTED', parameter: 'probe', title: 'CSRF proof', notes: 'Sends one inert state-changing request to an explicitly vetted local fixture endpoint; the response must prove the state change.', method: 'POST', requestBody: 'amount=1&destination=codesentinel-inert', requestHeaders: { 'content-type': 'application/x-www-form-urlencoded' }, matchesFinding: (finding) => finding.ruleId === 'CS-NODE-018' },
  { type: 'webhook_signature', categories: ['webhook_signature'], marker: 'CODESENTINEL_PROOF_WEBHOOK_ACCEPTED', parameter: 'probe', title: 'Webhook signature proof', notes: 'Sends a fixed invalid signature and bounded body; only explicit acceptance proves the missing-signature control.', method: 'POST', requestBody: '{"event":"codesentinel-inert"}', requestHeaders: { 'content-type': 'application/json', 'x-codesentinel-signature': 'invalid-codesentinel-signature' }, matchesFinding: (finding) => finding.ruleId === 'CS-NODE-019' },
  { type: 'mass_assignment', categories: ['mass_assignment'], marker: 'CODESENTINEL_PROOF_ADMIN_ASSIGNED', parameter: 'probe', title: 'Mass-assignment proof', notes: 'Submits one inert profile update containing a forbidden role field; the oracle requires the server to report that role was applied.', method: 'POST', requestBody: 'displayName=CodeSentinel&role=admin', requestHeaders: { 'content-type': 'application/x-www-form-urlencoded' }, matchesFinding: (finding) => finding.ruleId === 'CS-NODE-020' },
  { type: 'unrestricted_upload', categories: ['file_upload'], marker: 'CODESENTINEL_PROOF_UPLOAD_ACCEPTED', parameter: 'probe', title: 'Unrestricted upload proof', notes: 'Uploads a bounded inert text payload to a vetted local endpoint; no executable content or persistent external target is used.', method: 'POST', requestBody: 'codesentinel-inert-upload', requestHeaders: { 'content-type': 'text/plain', 'x-codesentinel-filename': 'codesentinel.txt' }, matchesFinding: (finding) => finding.ruleId === 'CS-NODE-010' },
];

function safeSourceAdapter(type: ProofCaseType): typeof SAFE_SOURCE_ADAPTERS[number] | null {
  return SAFE_SOURCE_ADAPTERS.find((adapter) => adapter.type === type) ?? null;
}

type RegisteredProofAdapter = SecurityProofAdapter | SourceProofAdapter;
const proofAdapterRegistry = (): RegisteredProofAdapter[] => [...EXECUTABLE_ADAPTERS, ...SAFE_SOURCE_ADAPTERS];

function registeredAdapter(type: ProofCaseType): RegisteredProofAdapter | null {
  return proofAdapterRegistry().find((adapter) => adapter.type === type) ?? null;
}

function isLocalProofTarget(target: RuntimeTarget): boolean {
  try {
    const hostname = new URL(target.allowedOrigin).hostname.toLowerCase().replace(/\.$/, '');
    return hostname === 'localhost' || hostname === '::1' || hostname.startsWith('127.');
  } catch { return false; }
}

function adapterForCandidate(candidateType: string): SecurityProofAdapter | null {
  const adapter = proofAdapterRegistry().find((item) => 'candidateTypes' in item && item.candidateTypes.includes(candidateType));
  return adapter && 'execute' in adapter ? adapter : null;
}

export function listSecurityProofAdapters(): Array<Pick<SecurityProofAdapter, 'type' | 'candidateTypes'>> {
  return [
    ...EXECUTABLE_ADAPTERS.map(({ type, candidateTypes }) => ({ type, candidateTypes: [...candidateTypes] })),
    ...SAFE_SOURCE_ADAPTERS.map(({ type, categories }) => ({ type, candidateTypes: [...categories] })),
  ];
}

export function buildSecurityProofCaseTemplate(type: ProofCaseType): SecurityProofCase {
  return metadata(type, 'benchmark-template');
}

export function listSecurityProofCases(config: AppConfig): SecurityProofCase[] {
  const routes = discoverRoutes(config);
  const access = routes.ok ? analyzeAccessControl(config, routes.data.entries) : null;
  const cases: SecurityProofCase[] = [];
  if (access && routes.ok) for (const finding of access.findings) {
    const entry = routes.data.entries.find((candidate) => candidate.id === finding.routeId);
    const adapter = adapterForCandidate(finding.candidateType);
    if (entry && adapter) cases.push(adapter.buildCase(finding.id, entry.method, entry.path));
  }
  return cases.sort((a, b) => a.id.localeCompare(b.id));
}

function receiptForBlocked(findingId: string, proofCase: SecurityProofCase, reason: string, sourceRefs: string[] = []): SecurityReceipt {
  return { receiptId: `receipt-${hash(`${findingId}|${proofCase.id}|${reason}`)}`, findingId, proofCase, status: 'blocked', redactedRequest: null, responseFacts: [], oracle: 'blocked', whyProven: '', sourceRefs, evidenceRefs: [], remediationRef: null, reVerification: { status: null, receiptId: null }, replayContract: null, replayOfReceiptId: null, beforeAfter: null, limitation: reason };
}

export function listSecurityReceiptsForFinding(findingId: string): SecurityReceipt[] {
  return [...receipts.values()].filter((receipt) => receipt.findingId === findingId).map((receipt) => detachedRedacted(receipt));
}

export function linkSecurityReceiptToRemediation(findingId: string, receiptId: string, remediationId: string): ToolOutcome<SecurityReceipt> {
  const receipt = receipts.get(receiptId);
  if (!receipt || receipt.findingId !== findingId || receipt.status !== 'verified') return err('VERIFICATION_INCONCLUSIVE', 'A verified original receipt is required before it can be bound to remediation.');
  if (receipt.remediationRef && receipt.remediationRef !== remediationId) return err('VERIFICATION_INCONCLUSIVE', 'The original receipt is already bound to a different remediation.');
  const linked = detachedRedacted({ ...receipt, remediationRef: remediationId });
  receipts.set(receiptId, linked);
  return ok(detachedRedacted(linked));
}

export function resetSecurityProofsForTests(): void { receipts.clear(); }

async function findStaticCandidate(config: AppConfig, findingId: string): Promise<{ finding: SecurityFinding; entry: AttackSurfaceEntry; adapter: SourceProofAdapter } | null> {
  const scan = await scanProject(config);
  if (!scan.ok) return null;
  const finding = scan.data.findings.find((item) => item.id === findingId);
  if (!finding || !finding.file) return null;
  const routes = discoverRoutes(config);
  if (!routes.ok) return null;
  const entry = routes.data.entries.find((item) => item.file === finding.file && finding.line !== undefined && finding.line >= item.sourceRange.startLine && finding.line <= item.sourceRange.endLine);
  if (!entry) return null;
  const adapter = SAFE_SOURCE_ADAPTERS.find((item) => item.categories.includes(finding.category) && (!item.matchesFinding || item.matchesFinding(finding))) ?? null;
  return adapter ? { finding, entry, adapter } : null;
}

function proofPath(entry: AttackSurfaceEntry, adapter: SourceProofAdapter): string | null {
  if (hasUnresolvedSegment(entry.path) || entry.method !== 'GET' && entry.method !== 'ALL') return null;
  const parameter = proofParameter(entry, adapter);
  const value = encodeURIComponent(adapter.requestValue ?? adapter.marker);
  return `${entry.path}${entry.path.includes('?') ? '&' : '?'}${encodeURIComponent(parameter)}=${value}`;
}

function proofParameter(entry: AttackSurfaceEntry, adapter: SourceProofAdapter): string {
  return entry.queryParameters[0]?.name ?? entry.bodyParameters[0]?.name ?? adapter.parameter;
}

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_RESPONSE_BYTES = 200_000;

function replayContractFor(
  proofCase: SecurityProofCase,
  adapter: SourceProofAdapter,
  target: RuntimeTarget,
  parameterName: string,
  inertProbeValue: string,
): ProofReplayContract {
  return {
    proofType: proofCase.type,
    method: proofCase.requestShape.method,
    relativeRoute: proofCase.requestShape.path,
    parameterName,
    inertProbeValue,
    targetConstraints: {
      allowedOrigin: target.allowedOrigin,
      loopbackOnly: true,
      maxRequestsPerCase: Math.min(target.maxRequestsPerCase ?? 12, proofCase.maxRequests),
      requestTimeoutMs: target.requestTimeoutMs ?? DEFAULT_TIMEOUT_MS,
      maxResponseBytes: target.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
      maxRedirects: 0,
      allowDestructiveMethods: target.allowDestructiveMethods === true,
      vettedTestPath: target.vettedTestPaths?.includes(proofCase.requestShape.path) ? proofCase.requestShape.path : null,
    },
    sessionLabelReferences: [],
    requestHeaders: adapter.requestHeaders,
    requestBody: adapter.requestBody ?? null,
    oracleDefinition: {
      kind: adapter.oracleKind ?? (adapter.type === 'open_redirect' ? 'location_contains' : 'body_contains'),
      marker: adapter.marker,
      safeResult: 'not_reproduced',
    },
  };
}

async function executeSafeSourceProof(config: AppConfig, request: VerifyFindingRequest, candidate: Awaited<ReturnType<typeof findStaticCandidate>>): Promise<{ status: SecurityReceipt['status']; proofCase: SecurityProofCase; evidence: VerificationEvidence[]; summary: string }> {
  if (!candidate) throw new Error('unsupported proof candidate');
  const { finding, entry, adapter } = candidate;
  const method = adapter.method ?? 'GET';
  const proofCase = metadata(adapter.type, finding.id, method, entry.path, true, adapter.notes);
  proofCase.requestShape.body = adapter.requestBody ?? null;
  proofCase.requestShape.headers = Object.keys(adapter.requestHeaders ?? {});
  return executeSafeSourceProofCase(request, proofCase, adapter, replayContractFor(proofCase, adapter, request.target, proofParameter(entry, adapter), adapter.requestValue ?? adapter.marker));
}

async function executeSafeSourceProofCase(
  request: VerifyFindingRequest,
  proofCase: SecurityProofCase,
  adapter: SourceProofAdapter,
  persistedContract?: ProofReplayContract,
): Promise<{ status: SecurityReceipt['status']; proofCase: SecurityProofCase; evidence: VerificationEvidence[]; summary: string }> {
  if (!isLocalProofTarget(request.target)) return { status: 'blocked', proofCase, evidence: [], summary: 'Proof adapters only execute against localhost or loopback targets.' };
  const contract = persistedContract ?? (() => {
    const parameterName = adapter.parameter;
    const inertProbeValue = adapter.requestValue ?? adapter.marker;
    return replayContractFor(proofCase, adapter, request.target, parameterName, inertProbeValue);
  })();
  if (contract.proofType !== proofCase.type || contract.method !== proofCase.requestShape.method || contract.relativeRoute !== proofCase.requestShape.path || contract.parameterName.length === 0 || contract.inertProbeValue.length === 0) {
    return { status: 'blocked', proofCase, evidence: [], summary: 'The persisted replay contract does not match the original proof case.' };
  }
  if (!['GET', 'POST'].includes(contract.method) || hasUnresolvedSegment(contract.relativeRoute) || !contract.relativeRoute.startsWith('/') || contract.relativeRoute.includes('://')) {
    return { status: 'blocked', proofCase, evidence: [], summary: 'The persisted replay contract is not a concrete bounded proof target.' };
  }
  const requestMaxRequests = Math.min(request.target.maxRequestsPerCase ?? 12, proofCase.maxRequests);
  const requestTimeout = request.target.requestTimeoutMs ?? DEFAULT_TIMEOUT_MS;
  const requestMaxResponse = request.target.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  const requestedVettedPath = request.target.vettedTestPaths?.includes(contract.relativeRoute) ? contract.relativeRoute : null;
  if (contract.targetConstraints.allowedOrigin !== request.target.allowedOrigin || contract.targetConstraints.loopbackOnly !== isLocalProofTarget(request.target) || contract.targetConstraints.maxRequestsPerCase !== requestMaxRequests || contract.targetConstraints.requestTimeoutMs !== requestTimeout || contract.targetConstraints.maxResponseBytes !== requestMaxResponse || contract.targetConstraints.allowDestructiveMethods !== (request.target.allowDestructiveMethods === true) || contract.targetConstraints.vettedTestPath !== requestedVettedPath) {
    return { status: 'blocked', proofCase, evidence: [], summary: 'Replay target does not match the original proof target constraints.' };
  }
  const replayTarget: RuntimeTarget = { ...request.target, maxRequestsPerCase: contract.targetConstraints.maxRequestsPerCase, requestTimeoutMs: contract.targetConstraints.requestTimeoutMs, maxResponseBytes: contract.targetConstraints.maxResponseBytes, maxRedirects: 0 };
  const path = contract.method === 'GET'
    ? `${contract.relativeRoute}${contract.relativeRoute.includes('?') ? '&' : '?'}${encodeURIComponent(contract.parameterName)}=${encodeURIComponent(contract.inertProbeValue)}`
    : contract.relativeRoute;
  const evidence = [await issueRuntimeRequest(replayTarget, buildSessionMap(request.sessions ?? []), { method: contract.method as 'GET' | 'POST', path, headers: contract.requestHeaders, body: contract.requestBody ?? undefined, sessionId: contract.sessionLabelReferences[0] ?? null }, new RuntimeClientState(replayTarget))];
  const response = evidence[0]!.response;
  if (response.status === 0 || response.bodyTruncated || (adapter.type !== 'open_redirect' && /timed out|failed|blocked|redirect/i.test(evidence[0]!.note) && response.status >= 300)) return { status: 'blocked', proofCase, evidence, summary: evidence[0]!.note };
  const location = Object.entries(response.headers).find(([key]) => key.toLowerCase() === 'location')?.[1] ?? '';
  const headerText = Object.entries(response.headers).map(([key, value]) => `${key.toLowerCase()}:${value.toLowerCase()}`).join('\n');
  const cookieSummary = Object.entries(response.headers).find(([key]) => key.toLowerCase() === 'set-cookie')?.[1].toLowerCase() ?? '';
  const proved = adapter.oracleKind === 'cookie_flags_incomplete'
    ? cookieSummary.length > 0 && !['httponly', 'samesite', 'secure'].every((flag) => cookieSummary.includes(flag))
    : adapter.oracleKind === 'header_contains'
    ? headerText.includes(adapter.marker.toLowerCase())
    : adapter.type === 'open_redirect'
      ? response.status >= 300 && response.status < 400 && location.includes(adapter.marker)
      : response.bodySnippet.includes(adapter.marker);
  if (proved) return { status: 'verified', proofCase, evidence, summary: `${adapter.title} semantic oracle matched the fixture proof marker; HTTP status alone was not used.` };
  if (response.status >= 200 && response.status < 300) return { status: 'not_reproduced', proofCase, evidence, summary: `${adapter.title} received a response without the required semantic oracle marker.` };
  return { status: 'not_reproduced', proofCase, evidence, summary: `${adapter.title} did not produce the required semantic oracle.` };
}

function sourceReceipt(
  findingId: string,
  execution: Awaited<ReturnType<typeof executeSafeSourceProofCase>>,
  sourceRefs: string[],
  evidenceRefs: string[],
  remediationRef: string | null = null,
  replayContract: ProofReplayContract | null = null,
  replayOfReceiptId: string | null = null,
  beforeAfter: SecurityReceipt['beforeAfter'] = null,
): SecurityReceipt {
  const responseFacts = execution.evidence.map((item) => ({ status: item.response.status, headers: item.response.headers, bodySnippet: item.response.bodySnippet, finalUrl: item.response.finalUrl }));
  return detachedRedacted({
    receiptId: `receipt-${hash(`${findingId}|${execution.status}|${remediationRef ?? 'initial'}|${JSON.stringify(responseFacts)}`)}`,
    findingId,
    proofCase: execution.proofCase,
    status: execution.status,
    redactedRequest: execution.evidence[0] ? { ...execution.evidence[0].request } : null,
    responseFacts,
    oracle: execution.status,
    whyProven: execution.status === 'verified' ? execution.summary : '',
    sourceRefs,
    evidenceRefs,
    remediationRef,
    reVerification: { status: null, receiptId: null },
    replayContract,
    replayOfReceiptId,
    beforeAfter,
    limitation: execution.status === 'verified' ? null : execution.summary,
  });
}

/** Replays a previously verified source proof after a controlled remediation.
 * The original static finding is intentionally not re-read: a successful fix
 * is expected to remove it. The stored proof case supplies only the original
 * bounded route shape; Phase 6 still validates the target and request. */
export async function replaySecurityProof(
  config: AppConfig,
  request: VerifyFindingRequest,
  originalReceipt: SecurityReceipt,
  remediationId: string
): Promise<ToolOutcome<SecurityReceipt>> {
  const registered = registeredAdapter(originalReceipt.proofCase.type);
  const adapter = registered && !('execute' in registered) ? registered : null;
  const original = receipts.get(originalReceipt.receiptId);
  if (!adapter || !original || original.status !== 'verified' || originalReceipt.status !== 'verified') return err('UNSUPPORTED_CANDIDATE_TYPE', 'Only a previously verified source proof receipt can be replayed by the proof engine.');
  if (original.findingId !== originalReceipt.findingId || original.findingId !== request.findingId || original.remediationRef !== originalReceipt.remediationRef || original.remediationRef !== remediationId) return err('VERIFICATION_INCONCLUSIVE', 'The replay requires a verified original receipt already bound to this remediation.');
  if (!original.replayContract || JSON.stringify(original.replayContract) !== JSON.stringify(originalReceipt.replayContract)) return err('VERIFICATION_INCONCLUSIVE', 'The supplied original receipt replay contract does not match the persisted contract.');
  const execution = await executeSafeSourceProofCase(request, original.proofCase, adapter, original.replayContract);
  const replay = sourceReceipt(request.findingId, execution, original.sourceRefs, [...original.evidenceRefs, `remediation:${remediationId}`], remediationId, original.replayContract, original.receiptId, { beforeStatus: original.status, afterStatus: execution.status });
  if (original) {
    receipts.set(original.receiptId, detachedRedacted({ ...original, remediationRef: remediationId, reVerification: { status: replay.status, receiptId: replay.receiptId } }));
  }
  return ok(storeReceipt(replay));
}

export async function proveSecurityFinding(config: AppConfig, request: VerifyFindingRequest): Promise<ToolOutcome<SecurityReceipt>> {
  const cases = listSecurityProofCases(config);
  const proofCase = cases.find((item) => item.findingId === request.findingId);
  if (!proofCase) {
    const candidate = await findStaticCandidate(config, request.findingId);
    if (!candidate) {
      const receipt = receiptForBlocked(request.findingId, metadata('sql_injection', request.findingId), 'No executable proof adapter was established from the current route/static inventory.');
      return ok(storeReceipt(receipt));
    }
    const execution = await executeSafeSourceProof(config, request, candidate);
    const safe = sourceReceipt(request.findingId, execution, [`${candidate.finding.file}:${candidate.finding.line ?? 0}`, `${candidate.entry.file}:${candidate.entry.line}`], [`static:${candidate.finding.id}`, `route:${candidate.entry.id}`], null, replayContractFor(execution.proofCase, candidate.adapter, request.target, proofParameter(candidate.entry, candidate.adapter), candidate.adapter.requestValue ?? candidate.adapter.marker));
    return ok(storeReceipt(safe));
  }
  const adapter = registeredAdapter(proofCase.type);
  if (!adapter || !('execute' in adapter)) {
    const receipt = receiptForBlocked(request.findingId, proofCase, `No executable adapter is registered for proof type "${proofCase.type}".`);
    return ok(storeReceipt(receipt));
  }
  const result = await adapter.execute(config, request);
  if (!result.ok) { const receipt = receiptForBlocked(request.findingId, proofCase, result.error.message, [request.findingId]); return ok(storeReceipt(receipt)); }
  const verification = result.data.result;
  const status = verification.status === 'verified' || verification.status === 'not_reproduced' || verification.status === 'inconclusive' || verification.status === 'blocked' ? verification.status : 'inconclusive';
  const responseFacts = verification.evidence.map((item) => ({ status: item.response.status, headers: item.response.headers, bodySnippet: item.response.bodySnippet, finalUrl: item.response.finalUrl }));
  const receipt: SecurityReceipt = { receiptId: `receipt-${hash(`${request.findingId}|${verification.status}|${JSON.stringify(responseFacts)}`)}`, findingId: request.findingId, proofCase, status, redactedRequest: verification.evidence[0] ? { ...verification.evidence[0].request } : null, responseFacts, oracle: verification.status, whyProven: verification.status === 'verified' ? verification.summary : '', sourceRefs: [result.data.finding.file, result.data.finding.path].filter(Boolean), evidenceRefs: verification.evidence.map((_, index) => `runtime:${request.findingId}:${index}`), remediationRef: null, reVerification: { status: null, receiptId: null }, replayContract: null, replayOfReceiptId: null, beforeAfter: null, limitation: verification.status === 'verified' ? null : verification.summary };
  const safe = detachedRedacted(receipt);
  return ok(storeReceipt(safe));
}

export function buildSecurityGraph(config: AppConfig): ToolOutcome<SecurityGraph> {
  const profile = runProjectDiscovery(config.projectRoot);
  const routes = discoverRoutes(config);
  if (!routes.ok) return err('INTERNAL_ERROR', 'Route inventory could not be built for the security graph.');
  const access = analyzeAccessControl(config, routes.data.entries);
  const listed = listFiles(config, { dirPath: '.', recursive: true, maxResults: 2_000 });
  const nodes: SecurityGraphNode[] = [];
  const edges: SecurityGraphEdge[] = [];
  const addNode = (node: SecurityGraphNode) => { if (!nodes.some((item) => item.id === node.id)) nodes.push(node); };
  const addEdge = (from: string, to: string, relation: string, confidence: SecurityGraphEdge['confidence'], evidenceRefs: string[]) => edges.push({ id: `edge-${hash(`${from}|${to}|${relation}`)}`, from, to, relation, confidence, evidenceRefs });
  if (listed.ok) for (const file of listed.data.filter((item) => item.type === 'file')) addNode({ id: `file:${file.path}`, kind: 'file', label: file.path, sourceRef: file.path });
  for (const route of routes.data.entries) {
    const routeId = `route:${route.id}`;
    addNode({ id: routeId, kind: 'route', label: `${route.method} ${route.path}`, sourceRef: `${route.file}:${route.line}` });
    const fileId = `file:${route.file}`;
    addNode({ id: fileId, kind: 'handler', label: route.handler, sourceRef: `${route.file}:${route.line}` });
    addEdge(routeId, fileId, 'handled_by', 'high', route.evidence.map((item) => `${route.file}:${route.line}`));
    for (const middleware of route.middleware) { const nodeId = `middleware:${middleware}`; addNode({ id: nodeId, kind: 'middleware', label: middleware, sourceRef: `${route.file}:${route.line}` }); addEdge(routeId, nodeId, 'uses_middleware', 'medium', route.evidence.map(() => `${route.file}:${route.line}`)); }
  }
  for (const finding of access.findings) {
    const findingId = `access:${finding.id}`;
    addNode({ id: findingId, kind: 'access_control', label: finding.title, sourceRef: finding.file });
    addEdge(`route:${finding.routeId}`, findingId, 'has_access_control_signal', finding.confidence, finding.evidence.map(() => `${finding.file}:${finding.line}`));
  }
  return ok({ nodes: nodes.slice(0, 4_000), edges: edges.slice(0, 8_000), limitations: [`Profile ecosystem: ${profile.ecosystem}.`, 'Cross-file graph edges are only emitted where existing route/access-control models provide a concrete relationship.', 'No full AST or taint graph is claimed for unsupported syntax.'] });
}

export { PROOF_CASE_TYPES };
