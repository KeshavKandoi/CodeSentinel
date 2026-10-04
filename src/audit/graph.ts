import crypto from 'node:crypto';
import type { AccessControlEntry } from '../access/types.js';
import type { SecurityGraph, SecurityGraphEdge, SecurityGraphNode } from '../proof/types.js';
import type { AuditFinding } from './types.js';

const MAX_NODES = 4_000;
const MAX_EDGES = 8_000;
const digest = (value: string): string => crypto.createHash('sha256').update(value).digest('hex').slice(0, 24);

export interface GraphReceiptRef {
  receiptId: string;
  status: string;
}

export function extendGraphWithAudit(base: SecurityGraph, findings: AuditFinding[], matrix: AccessControlEntry[], receipts: Map<string, GraphReceiptRef[]>): SecurityGraph {
  const nodes: SecurityGraphNode[] = [...base.nodes];
  const edges: SecurityGraphEdge[] = [...base.edges];
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edgeIds = new Set(edges.map((edge) => edge.id));
  const addNode = (node: SecurityGraphNode): void => {
    if (nodes.length < MAX_NODES && !nodeIds.has(node.id)) {
      nodeIds.add(node.id);
      nodes.push(node);
    }
  };
  const addEdge = (from: string, to: string, relation: string, confidence: SecurityGraphEdge['confidence'], evidenceRefs: string[]): void => {
    const id = `edge-${digest(`${from}|${to}|${relation}`)}`;
    if (edges.length >= MAX_EDGES || edgeIds.has(id) || !nodeIds.has(from) || !nodeIds.has(to)) return;
    edgeIds.add(id);
    edges.push({ id, from, to, relation, confidence, evidenceRefs });
  };

  for (const entry of matrix) {
    const routeNode = `route:${entry.routeId}`;
    if (!nodeIds.has(routeNode)) continue;
    for (const control of entry.authentication) {
      const id = `auth:${control.id}`;
      addNode({ id, kind: 'authentication_boundary', label: `${control.mechanism}:${control.name}`.slice(0, 120), sourceRef: `${control.file}:${control.line}` });
      addEdge(routeNode, id, 'protected_by', control.confidence, [`${control.file}:${control.line}`]);
    }
    for (const control of entry.authorization) {
      const id = `authz:${control.id}`;
      addNode({ id, kind: 'authorization_check', label: `${control.kind}:${control.name}`.slice(0, 120), sourceRef: `${control.file}:${control.line}` });
      addEdge(routeNode, id, 'authorized_by', control.confidence, [`${control.file}:${control.line}`]);
    }
    for (const check of entry.ownership) {
      const id = `ownership:${digest(`${check.file}|${check.line}|${check.parameter}`)}`;
      addNode({ id, kind: 'ownership_check', label: `${check.kind}:${check.parameter}`.slice(0, 120), sourceRef: `${check.file}:${check.line}` });
      addEdge(routeNode, id, 'ownership_enforced_by', check.confidence, [`${check.file}:${check.line}`]);
    }
  }

  for (const finding of findings) {
    const findingNode = `finding:${finding.id}`;
    addNode({ id: findingNode, kind: 'finding', label: `${finding.category}: ${finding.title}`.slice(0, 160), sourceRef: finding.file ? `${finding.file}:${finding.line ?? 0}` : finding.id });
    if (finding.file) {
      const fileNode = `file:${finding.file}`;
      addNode({ id: fileNode, kind: 'file', label: finding.file, sourceRef: finding.file });
      addEdge(findingNode, fileNode, 'located_in', 'high', [findingNode]);
    }
    if (finding.routeId) addEdge(findingNode, `route:${finding.routeId}`, 'affects_route', 'high', [findingNode]);
    for (const receipt of (receipts.get(finding.id) ?? []).slice(0, 5)) {
      const receiptNode = `receipt:${receipt.receiptId}`;
      addNode({ id: receiptNode, kind: 'proof_receipt', label: `proof ${receipt.status}`, sourceRef: receipt.receiptId });
      addEdge(findingNode, receiptNode, receipt.status === 'verified' ? 'proven_by' : 'proof_attempted', receipt.status === 'verified' ? 'high' : 'low', [receiptNode]);
    }
    for (const remediationId of finding.remediation.remediationIds.slice(0, 5)) {
      const remediationNode = `remediation:${remediationId}`;
      addNode({ id: remediationNode, kind: 'remediation', label: `remediation ${finding.remediation.status ?? 'recorded'}`, sourceRef: remediationId });
      addEdge(findingNode, remediationNode, 'remediated_by', 'medium', [findingNode]);
    }
  }

  return {
    nodes,
    edges,
    limitations: [...base.limitations, 'Finding, proof-receipt, and remediation nodes come from audit lifecycle records; no data-flow or taint edges are claimed.', 'Handler nodes carry handler names only; function-level nodes are not constructed.'],
  };
}
