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
import type { ProofCaseType, SecurityGraph, SecurityGraphEdge, SecurityGraphNode, SecurityProofCase, SecurityReceipt } from './types.js';
import { PROOF_CASE_TYPES } from './types.js';

const hash = (value: string): string => crypto.createHash('sha256').update(value).digest('hex').slice(0, 24);
const receipts = new Map<string, import('./types.js').SecurityReceipt>();
export interface SecurityProofAdapter {
  type: ProofCaseType;
  candidateTypes: string[];
  buildCase(findingId: string, method: string, path: string): SecurityProofCase;
  execute(config: AppConfig, request: VerifyFindingRequest): ReturnType<typeof verifyFinding>;
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

const SAFE_SOURCE_ADAPTERS: Array<{ type: ProofCaseType; categories: string[]; marker: string; requestValue?: string; parameter: string; title: string; notes: string }> = [
  { type: 'path_traversal', categories: ['path_traversal'], marker: 'CODESENTINEL_PROOF_OUTSIDE_ROOT', parameter: 'path', title: 'Path traversal proof', notes: 'Requires a local fixture to return the exact outside-root marker only when traversal succeeds.' },
  { type: 'open_redirect', categories: ['open_redirect', 'insecure_redirects'], marker: 'https://codesentinel.invalid/proof', requestValue: 'codesentinel-proof-redirect', parameter: 'url', title: 'Open redirect proof', notes: 'Uses a harmless local probe token; a fixture-controlled Location header provides the non-routable oracle and is never followed.' },
  { type: 'ssrf', categories: ['ssrf'], marker: 'CODESENTINEL_PROOF_SSRF_SENTINEL', parameter: 'url', title: 'SSRF proof', notes: 'Requires a local fixture-controlled SSRF oracle; no external or metadata target is used.' },
  { type: 'sql_injection', categories: ['injection'], marker: 'CODESENTINEL_PROOF_SQLI_SENTINEL', parameter: 'query', title: 'SQL injection proof', notes: 'Requires a local fixture-controlled semantic marker, never a generic SQL error.' },
  { type: 'command_injection', categories: ['command_injection'], marker: 'CODESENTINEL_PROOF_COMMAND_SENTINEL', parameter: 'command', title: 'Command injection proof', notes: 'Requires a local fixture-controlled marker; CodeSentinel never executes the supplied value.' },
  { type: 'xss_reflected', categories: ['xss'], marker: 'CODESENTINEL_PROOF_XSS_SENTINEL', parameter: 'q', title: 'Reflected XSS proof', notes: 'Verifies exact unencoded reflection of a unique inert marker, not script execution.' },
];

function safeSourceAdapter(type: ProofCaseType): typeof SAFE_SOURCE_ADAPTERS[number] | null {
  return SAFE_SOURCE_ADAPTERS.find((adapter) => adapter.type === type) ?? null;
}

function isLocalProofTarget(target: RuntimeTarget): boolean {
  try {
    const hostname = new URL(target.allowedOrigin).hostname.toLowerCase().replace(/\.$/, '');
    return hostname === 'localhost' || hostname === '::1' || hostname.startsWith('127.');
  } catch { return false; }
}

function adapterForCandidate(candidateType: string): SecurityProofAdapter | null {
  return EXECUTABLE_ADAPTERS.find((adapter) => adapter.candidateTypes.includes(candidateType)) ?? null;
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
  return { receiptId: `receipt-${hash(`${findingId}|${proofCase.id}|${reason}`)}`, findingId, proofCase, status: 'blocked', redactedRequest: null, responseFacts: [], oracle: 'blocked', whyProven: '', sourceRefs, evidenceRefs: [], remediationRef: null, reVerification: { status: null, receiptId: null }, limitation: reason };
}

export function listSecurityReceiptsForFinding(findingId: string): SecurityReceipt[] {
  return [...receipts.values()].filter((receipt) => receipt.findingId === findingId).map((receipt) => detachedRedacted(receipt));
}

export function resetSecurityProofsForTests(): void { receipts.clear(); }

async function findStaticCandidate(config: AppConfig, findingId: string): Promise<{ finding: SecurityFinding; entry: AttackSurfaceEntry; adapter: typeof SAFE_SOURCE_ADAPTERS[number] } | null> {
  const scan = await scanProject(config);
  if (!scan.ok) return null;
  const finding = scan.data.findings.find((item) => item.id === findingId);
  if (!finding || !finding.file) return null;
  const routes = discoverRoutes(config);
  if (!routes.ok) return null;
  const entry = routes.data.entries.find((item) => item.file === finding.file && finding.line !== undefined && finding.line >= item.sourceRange.startLine && finding.line <= item.sourceRange.endLine);
  if (!entry) return null;
  const adapter = SAFE_SOURCE_ADAPTERS.find((item) => item.categories.includes(finding.category)) ?? null;
  return adapter ? { finding, entry, adapter } : null;
}

function proofPath(entry: AttackSurfaceEntry, adapter: typeof SAFE_SOURCE_ADAPTERS[number]): string | null {
  if (hasUnresolvedSegment(entry.path) || entry.method !== 'GET' && entry.method !== 'ALL') return null;
  const parameter = entry.queryParameters[0]?.name ?? entry.bodyParameters[0]?.name ?? adapter.parameter;
  const value = encodeURIComponent(adapter.requestValue ?? adapter.marker);
  return `${entry.path}${entry.path.includes('?') ? '&' : '?'}${encodeURIComponent(parameter)}=${value}`;
}

async function executeSafeSourceProof(config: AppConfig, request: VerifyFindingRequest, candidate: Awaited<ReturnType<typeof findStaticCandidate>>): Promise<{ status: SecurityReceipt['status']; proofCase: SecurityProofCase; evidence: VerificationEvidence[]; summary: string }> {
  if (!candidate) throw new Error('unsupported proof candidate');
  const { finding, entry, adapter } = candidate;
  const proofCase = metadata(adapter.type, finding.id, 'GET', entry.path, true, adapter.notes);
  if (!isLocalProofTarget(request.target)) return { status: 'blocked', proofCase, evidence: [], summary: 'Proof adapters only execute against localhost or loopback targets.' };
  const path = proofPath(entry, adapter);
  if (!path) return { status: 'blocked', proofCase, evidence: [], summary: 'The route is not a concrete safe GET proof target.' };
  const evidence = [await issueRuntimeRequest(request.target, buildSessionMap(request.sessions ?? []), { method: 'GET', path, sessionId: null }, new RuntimeClientState(request.target))];
  const response = evidence[0]!.response;
  if (response.status === 0) return { status: 'blocked', proofCase, evidence, summary: evidence[0]!.note };
  const location = Object.entries(response.headers).find(([key]) => key.toLowerCase() === 'location')?.[1] ?? '';
  const proved = adapter.type === 'open_redirect'
    ? response.status >= 300 && response.status < 400 && location.includes(adapter.marker)
    : response.bodySnippet.includes(adapter.marker);
  if (proved) return { status: 'verified', proofCase, evidence, summary: `${adapter.title} semantic oracle matched the fixture proof marker; HTTP status alone was not used.` };
  if (response.status >= 200 && response.status < 300) return { status: 'inconclusive', proofCase, evidence, summary: `${adapter.title} received a response without the required semantic oracle marker.` };
  return { status: 'not_reproduced', proofCase, evidence, summary: `${adapter.title} did not produce the required semantic oracle.` };
}

export async function proveSecurityFinding(config: AppConfig, request: VerifyFindingRequest): Promise<ToolOutcome<SecurityReceipt>> {
  const cases = listSecurityProofCases(config);
  const proofCase = cases.find((item) => item.findingId === request.findingId);
  if (!proofCase) {
    const candidate = await findStaticCandidate(config, request.findingId);
    if (!candidate) {
      const receipt = receiptForBlocked(request.findingId, metadata('sql_injection', request.findingId), 'No executable proof adapter was established from the current route/static inventory.');
      receipts.set(receipt.receiptId, receipt);
      return ok(receipt);
    }
    const execution = await executeSafeSourceProof(config, request, candidate);
    const responseFacts = execution.evidence.map((item) => ({ status: item.response.status, headers: item.response.headers, bodySnippet: item.response.bodySnippet, finalUrl: item.response.finalUrl }));
    const receipt: SecurityReceipt = { receiptId: `receipt-${hash(`${request.findingId}|${execution.status}|${JSON.stringify(responseFacts)}`)}`, findingId: request.findingId, proofCase: execution.proofCase, status: execution.status, redactedRequest: execution.evidence[0] ? { ...execution.evidence[0].request } : null, responseFacts, oracle: execution.status, whyProven: execution.status === 'verified' ? execution.summary : '', sourceRefs: [`${candidate.finding.file}:${candidate.finding.line ?? 0}`, `${candidate.entry.file}:${candidate.entry.line}`], evidenceRefs: [`static:${candidate.finding.id}`, `route:${candidate.entry.id}`], remediationRef: null, reVerification: { status: null, receiptId: null }, limitation: execution.status === 'verified' ? null : execution.summary };
    const safe = detachedRedacted(receipt); receipts.set(safe.receiptId, safe); return ok(safe);
  }
  const adapter = proofCase.type === 'idor_bola' ? EXECUTABLE_ADAPTERS[0] : EXECUTABLE_ADAPTERS.find((item) => item.type === proofCase.type);
  if (!adapter) {
    const receipt = receiptForBlocked(request.findingId, proofCase, `No executable adapter is registered for proof type "${proofCase.type}".`);
    receipts.set(receipt.receiptId, receipt);
    return ok(receipt);
  }
  const result = await adapter.execute(config, request);
  if (!result.ok) { const receipt = receiptForBlocked(request.findingId, proofCase, result.error.message, [request.findingId]); receipts.set(receipt.receiptId, receipt); return ok(receipt); }
  const verification = result.data.result;
  const status = verification.status === 'verified' || verification.status === 'not_reproduced' || verification.status === 'inconclusive' || verification.status === 'blocked' ? verification.status : 'inconclusive';
  const responseFacts = verification.evidence.map((item) => ({ status: item.response.status, headers: item.response.headers, bodySnippet: item.response.bodySnippet, finalUrl: item.response.finalUrl }));
  const receipt: SecurityReceipt = { receiptId: `receipt-${hash(`${request.findingId}|${verification.status}|${JSON.stringify(responseFacts)}`)}`, findingId: request.findingId, proofCase, status, redactedRequest: verification.evidence[0] ? { ...verification.evidence[0].request } : null, responseFacts, oracle: verification.status, whyProven: verification.status === 'verified' ? verification.summary : '', sourceRefs: [result.data.finding.file, result.data.finding.path].filter(Boolean), evidenceRefs: verification.evidence.map((_, index) => `runtime:${request.findingId}:${index}`), remediationRef: null, reVerification: { status: null, receiptId: null }, limitation: verification.status === 'verified' ? null : verification.summary };
  const safe = detachedRedacted(receipt);
  receipts.set(safe.receiptId, safe);
  return ok(safe);
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
