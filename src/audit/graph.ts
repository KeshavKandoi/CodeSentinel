import crypto from 'node:crypto';
import type { AccessControlEntry } from '../access/types.js';
import type { SecurityGraph, SecurityGraphEdge, SecurityGraphNode } from '../proof/types.js';
import type { AuditFinding } from './types.js';
import { canonicalCategory, normalizeFile } from './identity.js';

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

  for (const relation of findingRelationships(findings)) {
    addEdge(`finding:${relation.from}`, `finding:${relation.to}`, relation.relation, relation.confidence, [`finding:${relation.from}`, `finding:${relation.to}`]);
  }

  return {
    nodes,
    edges,
    limitations: [...base.limitations, 'Finding, proof-receipt, and remediation nodes come from audit lifecycle records; no data-flow or taint edges are claimed.', 'Handler nodes carry handler names only; function-level nodes are not constructed.'],
  };
}

export interface FindingRelationship {
  from: string;
  to: string;
  relation: 'correlates_with' | 'duplicate_of';
  confidence: 'high' | 'medium';
}

export interface NearDuplicateGroup {
  anchorId: string;
  findingIds: string[];
  category: string;
  file: string;
  route: string | null;
  reason: string;
}

const MAX_GROUP = 50;
const MAX_RELATIONSHIPS = 2_000;
const NEAR_LINE_DISTANCE = 5;
const MAX_NEAR_GROUPS = 100;
const MAX_GROUP_MEMBERS = 20;
const byId = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

function relate(low: AuditFinding, high: AuditFinding): FindingRelationship | null {
  const file = normalizeFile(low.file);
  const sameFile = file !== null && file === normalizeFile(high.file);
  const sameCategory = canonicalCategory(low.category) === canonicalCategory(high.category);
  if (sameFile && sameCategory && low.route === high.route && low.line !== null && low.line === high.line) {
    return { from: high.id, to: low.id, relation: 'duplicate_of', confidence: 'high' };
  }
  const lowSources = new Set(low.sources.map((source) => source.sourceId));
  if (high.sources.some((source) => lowSources.has(source.sourceId))) {
    return { from: low.id, to: high.id, relation: 'correlates_with', confidence: 'high' };
  }
  if (sameFile && !sameCategory && low.route !== null && low.route === high.route) {
    return { from: low.id, to: high.id, relation: 'correlates_with', confidence: 'medium' };
  }
  return null;
}

export function findingRelationships(findings: readonly AuditFinding[]): FindingRelationship[] {
  const sorted = [...findings].sort((a, b) => byId(a.id, b.id));
  const candidates = new Map<string, [AuditFinding, AuditFinding]>();
  const byFile = new Map<string, AuditFinding[]>();
  const bySource = new Map<string, AuditFinding[]>();
  const push = (map: Map<string, AuditFinding[]>, key: string, finding: AuditFinding): void => {
    const list = map.get(key);
    if (list) list.push(finding);
    else map.set(key, [finding]);
  };
  for (const finding of sorted) {
    const file = normalizeFile(finding.file);
    if (file !== null) push(byFile, file, finding);
    for (const sourceId of new Set(finding.sources.map((source) => source.sourceId))) push(bySource, sourceId, finding);
  }
  for (const group of [...byFile.values(), ...bySource.values()]) {
    const bounded = group.slice(0, MAX_GROUP);
    for (let i = 0; i < bounded.length; i++) {
      for (let j = i + 1; j < bounded.length; j++) {
        const a = bounded[i];
        const b = bounded[j];
        if (a.id === b.id) continue;
        const pair: [AuditFinding, AuditFinding] = byId(a.id, b.id) < 0 ? [a, b] : [b, a];
        candidates.set(`${pair[0].id}|${pair[1].id}`, pair);
      }
    }
  }
  const result: FindingRelationship[] = [];
  for (const key of [...candidates.keys()].sort(byId)) {
    const pair = candidates.get(key) as [AuditFinding, AuditFinding];
    const relation = relate(pair[0], pair[1]);
    if (relation) result.push(relation);
    if (result.length >= MAX_RELATIONSHIPS) break;
  }
  return result;
}

function typeKeys(finding: AuditFinding): Set<string> {
  const keys = new Set<string>();
  for (const source of finding.sources) {
    if (source.origin === 'deep_analysis' || source.origin === 'remediation_record') continue;
    const key = source.candidateType ?? source.ruleId;
    if (key) keys.add(key);
  }
  return keys;
}

function compatibleTypes(a: AuditFinding, b: AuditFinding): boolean {
  const x = typeKeys(a);
  const y = typeKeys(b);
  if (x.size === 0 || y.size === 0) return true;
  return [...x].some((key) => y.has(key));
}

function isNearDuplicate(a: AuditFinding, b: AuditFinding): boolean {
  const file = normalizeFile(a.file);
  if (file === null || file !== normalizeFile(b.file)) return false;
  if (canonicalCategory(a.category) !== canonicalCategory(b.category)) return false;
  if (!compatibleTypes(a, b)) return false;
  if (a.route !== null && b.route !== null) return a.route === b.route;
  return a.line !== null && b.line !== null && Math.abs(a.line - b.line) <= NEAR_LINE_DISTANCE;
}

export function findNearDuplicates(findings: readonly AuditFinding[]): NearDuplicateGroup[] {
  const sorted = [...findings].sort((a, b) => byId(a.id, b.id));
  const buckets = new Map<string, AuditFinding[]>();
  for (const finding of sorted) {
    const file = normalizeFile(finding.file);
    if (file === null) continue;
    const list = buckets.get(file);
    if (list) list.push(finding);
    else buckets.set(file, [finding]);
  }
  const assigned = new Set<string>();
  const groups: NearDuplicateGroup[] = [];
  for (const anchor of sorted) {
    const file = normalizeFile(anchor.file);
    if (file === null || assigned.has(anchor.id)) continue;
    const members = (buckets.get(file) ?? [])
      .filter((other) => other.id !== anchor.id && !assigned.has(other.id) && isNearDuplicate(anchor, other))
      .slice(0, MAX_GROUP_MEMBERS - 1);
    if (members.length === 0) continue;
    assigned.add(anchor.id);
    for (const member of members) assigned.add(member.id);
    const category = canonicalCategory(anchor.category);
    groups.push({
      anchorId: anchor.id,
      findingIds: [anchor.id, ...members.map((member) => member.id)].sort(byId),
      category,
      file,
      route: anchor.route,
      reason: `Same category "${category}" in ${file}${anchor.route !== null ? ` on ${anchor.route}` : ` within ${NEAR_LINE_DISTANCE} lines`}`,
    });
    if (groups.length >= MAX_NEAR_GROUPS) break;
  }
  return groups;
}
