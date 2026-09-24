import crypto from 'node:crypto';
import type { AppConfig } from '../config.js';
import { analyzeAccessControl } from '../access/engine.js';
import { discoverRoutes } from '../routes/engine.js';
import { runProjectDiscovery } from '../discovery/projectDiscovery.js';
import { listFiles } from '../fs/fsOperations.js';
import { verifyFinding } from '../runtime/engine.js';
import type { VerifyFindingRequest } from '../runtime/engine.js';
import { detachedRedacted } from '../report/redaction.js';
import { err, ok, type ToolOutcome } from '../types.js';
import type { ProofCaseType, SecurityGraph, SecurityGraphEdge, SecurityGraphNode, SecurityProofCase, SecurityReceipt } from './types.js';
import { PROOF_CASE_TYPES } from './types.js';

const hash = (value: string): string => crypto.createHash('sha256').update(value).digest('hex').slice(0, 24);
const receipts = new Map<string, import('./types.js').SecurityReceipt>();
const accessType = (candidate: string): ProofCaseType | null => ({ idor_candidate: 'idor_bola', user_resource_access: 'idor_bola', missing_authentication: 'missing_authentication', missing_authorization: 'missing_authorization', inconsistent_authorization: 'authorization_inconsistency' } as Record<string, ProofCaseType>)[candidate] ?? null;

const metadata = (type: ProofCaseType, findingId: string, method = 'GET', path = '/'): SecurityProofCase => ({
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
});

export function buildSecurityProofCaseTemplate(type: ProofCaseType): SecurityProofCase {
  return metadata(type, 'benchmark-template');
}

export function listSecurityProofCases(config: AppConfig): SecurityProofCase[] {
  const routes = discoverRoutes(config);
  const access = routes.ok ? analyzeAccessControl(config, routes.data.entries) : null;
  const cases: SecurityProofCase[] = [];
  if (access && routes.ok) for (const finding of access.findings) {
    const entry = routes.data.entries.find((candidate) => candidate.id === finding.routeId);
    const type = accessType(finding.candidateType);
    if (entry && type) cases.push(metadata(type, finding.id, entry.method, entry.path));
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

export async function proveSecurityFinding(config: AppConfig, request: VerifyFindingRequest): Promise<ToolOutcome<SecurityReceipt>> {
  const cases = listSecurityProofCases(config);
  const proofCase = cases.find((item) => item.findingId === request.findingId);
  if (!proofCase) {
    const receipt = receiptForBlocked(request.findingId, metadata('sql_injection', request.findingId), 'No supported proof case was established from the current route/access-control inventory.');
    receipts.set(receipt.receiptId, receipt);
    return ok(receipt);
  }
  const result = await verifyFinding(config, request);
  if (!result.ok) { const receipt = receiptForBlocked(request.findingId, proofCase, result.error.message, [request.findingId]); receipts.set(receipt.receiptId, receipt); return ok(receipt); }
  const verification = result.data.result;
  const status = verification.status === 'verified' || verification.status === 'not_reproduced' || verification.status === 'inconclusive' || verification.status === 'blocked' ? verification.status : 'inconclusive';
  const responseFacts = verification.evidence.map((item) => ({ status: item.response.status, bodySnippet: item.response.bodySnippet, finalUrl: item.response.finalUrl }));
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
