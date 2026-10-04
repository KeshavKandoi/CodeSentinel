import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { AppConfig } from '../../src/config.js';
import { addOrMerge, compareFindings, createFinding, synthesizeEvidence } from '../../src/audit/identity.js';
import { calculateRiskScore } from '../../src/audit/scoring.js';
import { advanceToVerified } from '../../src/audit/lifecycle.js';
import { extendGraphWithAudit, findNearDuplicates, findingRelationships } from '../../src/audit/graph.js';
import { runSecurityAuditPipeline } from '../../src/audit/pipeline.js';
import type { AuditFinding, FindingSource, FindingStatus, Severity } from '../../src/audit/types.js';

type Origin = FindingSource['origin'];
const STAGES = { security_scan: 'static_scan', access_control: 'access_control', deep_analysis: 'deep_analysis', remediation_record: 'runtime_proof' } as const;
const FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/access-control-express', import.meta.url)));
const config = { projectRoot: FIXTURE, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 1000 } as AppConfig;
const emptyGraph = { nodes: [], edges: [], limitations: [] };

function src(origin: Origin, sourceId: string, extra: Partial<FindingSource> = {}): FindingSource {
  return {
    stage: STAGES[origin],
    origin,
    sourceId,
    ruleId: origin === 'deep_analysis' ? null : 'RULE-1',
    category: 'authentication',
    candidateType: origin === 'access_control' ? 'missing_authentication' : null,
    routePath: origin === 'access_control' ? '/admin' : null,
    ...extra,
  };
}

function mk(origin: Origin, sourceId: string, over: Partial<Parameters<typeof createFinding>[0]> = {}): AuditFinding {
  return createFinding({
    id: 'cs-test',
    category: 'missing_authentication',
    title: 'Admin route lacks authentication',
    severity: 'high',
    confidence: 'medium',
    file: 'src/app.ts',
    line: 10,
    route: 'GET /admin',
    routeId: 'r1',
    sources: [src(origin, sourceId)],
    evidence: ['static evidence'],
    recommendation: 'Add authentication.',
    ...over,
  });
}

function merged(...items: AuditFinding[]): AuditFinding {
  const map = new Map<string, AuditFinding>();
  for (const item of items) addOrMerge(map, item);
  return map.get(items[0].id) as AuditFinding;
}

const gf = (id: string, over: Partial<Parameters<typeof createFinding>[0]> = {}): AuditFinding => mk('security_scan', `src-${id}`, { id, ...over });
const relEdges = (graph: { edges: Array<{ relation: string }> }) => graph.edges.filter((edge) => edge.relation === 'correlates_with' || edge.relation === 'duplicate_of');

describe('Phase 7 risk scoring', () => {
  it('always yields an integer from 0 through 100', () => {
    const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    const statuses: FindingStatus[] = ['candidate', 'analyzed', 'proof_eligible', 'verified', 'not_reproduced', 'unsupported', 'blocked', 'inconclusive', 'remediation_applied', 'verified_resolved'];
    for (const severity of severities) {
      for (const status of statuses) {
        for (const confidence of ['high', 'medium', 'low'] as const) {
          const finding = mk('security_scan', 's-1', { severity, confidence });
          finding.status = status;
          const score = calculateRiskScore(finding);
          expect(Number.isInteger(score)).toBe(true);
          expect(score).toBeGreaterThanOrEqual(0);
          expect(score).toBeLessThanOrEqual(100);
        }
      }
    }
  });

  it('is deterministic and does not mutate the finding', () => {
    const finding = mk('security_scan', 's-1');
    const before = JSON.stringify(finding);
    expect(calculateRiskScore(finding)).toBe(calculateRiskScore(finding));
    expect(JSON.stringify(finding)).toBe(before);
  });

  it('applies the 40/35 severity and verification weights', () => {
    const critical = mk('security_scan', 's-1', { severity: 'critical' });
    const info = mk('security_scan', 's-1', { severity: 'info' });
    expect(calculateRiskScore(critical) - calculateRiskScore(info)).toBeGreaterThanOrEqual(39);
    expect(calculateRiskScore(critical) - calculateRiskScore(info)).toBeLessThanOrEqual(41);
    const verified = mk('security_scan', 's-1');
    verified.status = 'verified';
    const candidate = mk('security_scan', 's-1');
    const inconclusive = mk('security_scan', 's-1');
    inconclusive.status = 'inconclusive';
    expect(calculateRiskScore(verified) - calculateRiskScore(candidate)).toBeGreaterThanOrEqual(34);
    expect(calculateRiskScore(verified) - calculateRiskScore(candidate)).toBeLessThanOrEqual(36);
    expect(calculateRiskScore(verified)).toBeGreaterThan(calculateRiskScore(inconclusive));
  });

  it('treats unknown exposure as neutral rather than guessing', () => {
    const noRoute = mk('access_control', 'a-1', { route: null, routeId: null });
    const unresolved = mk('access_control', 'a-2', { sources: [src('access_control', 'a-2', { routePath: 'unknown' })] });
    expect(calculateRiskScore(noRoute)).toBe(calculateRiskScore(unresolved));
  });

  it('scores multi-engine evidence above single-engine evidence', () => {
    const single = mk('security_scan', 's-1');
    const multi = mk('security_scan', 's-1');
    multi.sources.push(src('deep_analysis', 'd-1'));
    expect(calculateRiskScore(multi)).toBeGreaterThan(calculateRiskScore(single));
  });

  it('never lets a static finding become verified, whatever its score', () => {
    const finding = mk('security_scan', 's-1');
    finding.riskScore = 100;
    const receipt = { status: 'verified', oracle: 'verified', whyProven: 'proved', proofCase: { executable: true }, findingId: 's-1' } as any;
    expect(() => advanceToVerified(finding, receipt)).toThrow();
    expect(finding.status).toBe('candidate');
  });
});

describe('Phase 7 pipeline integration', () => {
  it('assigns final riskScore and synthesis to every finding without verifying anything', async () => {
    const outcome = await runSecurityAuditPipeline(config, {} as any);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const findings = outcome.data.findings;
    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      expect(Number.isInteger(finding.riskScore)).toBe(true);
      expect(finding.riskScore).toBe(calculateRiskScore(finding));
      expect(typeof finding.evidenceSynthesis).toBe('string');
      expect(finding.evidenceSynthesis).not.toContain('Runtime proof verified');
      expect(finding.status).not.toBe('verified');
    }
    for (let i = 1; i < findings.length; i++) expect(compareFindings(findings[i - 1], findings[i])).toBeLessThanOrEqual(0);
  }, 60_000);
});

describe('Phase 7 correlation', () => {
  it('merges scanner and access-control evidence', () => {
    const result = merged(mk('security_scan', 's-1'), mk('access_control', 'a-1'));
    expect(result.sources).toHaveLength(2);
    expect(result.correlation).toEqual({ sourceIds: ['a-1', 's-1'], reason: 'Static scanner + Access-control analysis', engineCount: 2 });
  });

  it('merges scanner and deep-analysis evidence', () => {
    const result = merged(mk('security_scan', 's-1'), mk('deep_analysis', 'd-1'));
    expect(result.correlation).toEqual({ sourceIds: ['d-1', 's-1'], reason: 'Static scanner + Deep heuristic analysis', engineCount: 2 });
  });

  it('merges scanner, access-control and deep-analysis evidence', () => {
    const result = merged(mk('security_scan', 's-1'), mk('access_control', 'a-1'), mk('deep_analysis', 'd-1'));
    expect(result.correlation).toEqual({ sourceIds: ['a-1', 'd-1', 's-1'], reason: 'Static scanner + Access-control analysis + Deep heuristic analysis', engineCount: 3 });
  });

  it('deduplicates duplicate source ids and gives single-source findings no correlation', () => {
    const result = merged(mk('security_scan', 's-1'), mk('security_scan', 's-1'));
    expect(result.sources).toHaveLength(1);
    expect(result.correlation).toBeUndefined();
    expect(mk('security_scan', 's-1').correlation).toBeUndefined();
  });

  it('produces identical correlation regardless of merge order', () => {
    const forward = merged(mk('security_scan', 'z-1'), mk('access_control', 'a-1'), mk('deep_analysis', 'm-1'));
    const reverse = merged(mk('deep_analysis', 'm-1'), mk('access_control', 'a-1'), mk('security_scan', 'z-1'));
    expect(forward.correlation).toEqual(reverse.correlation);
    expect(forward.correlation?.sourceIds).toEqual(['a-1', 'm-1', 'z-1']);
  });

  it('does not let a heuristic escalate or relocate an authoritative finding', () => {
    const base = mk('security_scan', 's-1', { severity: 'medium', confidence: 'low', line: 10 });
    const lifecycleBefore = JSON.stringify({ status: base.status, classification: base.classification, proof: base.proof });
    const deep = mk('deep_analysis', 'd-1', { severity: 'critical', confidence: 'high', line: 2, title: 'Deep says critical' });
    const result = merged(base, deep);
    expect(result.severity).toBe('medium');
    expect(result.confidence).toBe('low');
    expect(result.line).toBe(10);
    expect(result.title).toBe('Admin route lacks authentication');
    expect(JSON.stringify({ status: result.status, classification: result.classification, proof: result.proof })).toBe(lifecycleBefore);
  });

  it('keeps secret-like evidence out of correlation metadata', () => {
    const deep = mk('deep_analysis', 'd-1', { evidence: ['token = ghp_abcdefghijklmnopqrstuvwxyz123456'] });
    const result = merged(mk('security_scan', 's-1'), deep);
    expect(JSON.stringify(result.correlation)).not.toContain('ghp_');
    expect(synthesizeEvidence(result)).not.toContain('ghp_');
  });
});

describe('Phase 7 evidence synthesis', () => {
  it('describes a scanner-only finding without other engines', () => {
    const text = synthesizeEvidence(mk('security_scan', 's-1'));
    expect(text).toContain('Static scanner detected');
    expect(text).not.toMatch(/Access-control|Deep heuristic|Runtime proof/);
  });

  it('describes scanner plus access-control evidence', () => {
    const text = synthesizeEvidence(merged(mk('security_scan', 's-1'), mk('access_control', 'a-1')));
    expect(text).toContain('Static scanner detected');
    expect(text).toContain('Access-control analysis detected');
    expect(text).not.toMatch(/Deep heuristic|Runtime proof/);
  });

  it('describes scanner plus deep evidence as heuristic', () => {
    const text = synthesizeEvidence(merged(mk('security_scan', 's-1'), mk('deep_analysis', 'd-1')));
    expect(text).toContain('Deep heuristic analysis flagged');
    expect(text).not.toMatch(/Access-control|Runtime proof/);
  });

  it('reports runtime verification only for a verified finding with a receipt', () => {
    const finding = mk('access_control', 'a-1');
    finding.status = 'verified';
    finding.proof = { receiptIds: ['r-1'], status: 'verified', attempted: true, fromPriorReceipt: false, note: null };
    expect(synthesizeEvidence(finding)).toContain('Runtime proof verified');
  });

  it('never claims runtime verification without a real verified receipt', () => {
    const spoofed = mk('access_control', 'a-1');
    spoofed.proof = { receiptIds: ['r-1'], status: 'verified', attempted: true, fromPriorReceipt: false, note: null };
    expect(synthesizeEvidence(spoofed)).not.toContain('Runtime proof verified');
    const noReceipt = mk('access_control', 'a-1');
    noReceipt.status = 'verified';
    expect(synthesizeEvidence(noReceipt)).not.toContain('Runtime proof verified');
  });

  it('redacts secrets and stays bounded', () => {
    const finding = mk('security_scan', 's-1', { file: `src/ghp_abcdefghijklmnopqrstuvwxyz123456.ts` });
    const text = synthesizeEvidence(finding);
    expect(text).not.toContain('ghp_abcdef');
    expect(text.length).toBeLessThanOrEqual(600);
  });

  it('is deterministic regardless of source order', () => {
    const a = merged(mk('security_scan', 's-1'), mk('access_control', 'a-1'), mk('deep_analysis', 'd-1'));
    const b = merged(mk('deep_analysis', 'd-1'), mk('access_control', 'a-1'), mk('security_scan', 's-1'));
    expect(synthesizeEvidence(a)).toBe(synthesizeEvidence(b));
    expect(synthesizeEvidence(a)).toBe(synthesizeEvidence(a));
  });
});

describe('Phase 7 graph relationships', () => {
  it('links findings on the same file and route with different categories', () => {
    const graph = extendGraphWithAudit(emptyGraph, [gf('cs-b', { category: 'missing_authorization', line: 30 }), gf('cs-a')], [], new Map());
    const edges = relEdges(graph) as Array<{ relation: string; from: string; to: string; confidence: string }>;
    expect(edges).toHaveLength(1);
    expect(edges[0]).toMatchObject({ relation: 'correlates_with', from: 'finding:cs-a', to: 'finding:cs-b', confidence: 'medium' });
  });

  it('marks identical canonical locations as duplicate_of without a second edge', () => {
    const edges = relEdges(extendGraphWithAudit(emptyGraph, [gf('cs-a'), gf('cs-b')], [], new Map())) as Array<{ relation: string; from: string; to: string }>;
    expect(edges).toHaveLength(1);
    expect(edges[0]).toMatchObject({ relation: 'duplicate_of', from: 'finding:cs-b', to: 'finding:cs-a' });
  });

  it('correlates findings that explicitly share a source id', () => {
    const a = gf('cs-a', { file: 'x.ts', route: null, routeId: null, category: 'xss', sources: [src('security_scan', 'shared')] });
    const b = gf('cs-b', { file: 'y.ts', route: null, routeId: null, category: 'sqli', sources: [src('access_control', 'shared')] });
    expect(findingRelationships([b, a])).toEqual([{ from: 'cs-a', to: 'cs-b', relation: 'correlates_with', confidence: 'high' }]);
  });

  it('adds no finding-to-finding edges for unrelated findings', () => {
    const a = gf('cs-a', { file: 'a.ts', route: 'GET /a', category: 'xss' });
    const b = gf('cs-b', { file: 'b.ts', route: 'GET /b', category: 'sqli' });
    const graph = extendGraphWithAudit(emptyGraph, [a, b], [], new Map());
    expect(relEdges(graph)).toHaveLength(0);
  });

  it('produces unique, order-independent edge ids', () => {
    const items = [gf('cs-a'), gf('cs-b'), gf('cs-c', { category: 'missing_authorization', line: 40 })];
    const forward = extendGraphWithAudit(emptyGraph, items, [], new Map());
    const reverse = extendGraphWithAudit(emptyGraph, [...items].reverse(), [], new Map());
    expect(new Set(forward.edges.map((edge) => edge.id)).size).toBe(forward.edges.length);
    expect(relEdges(forward)).toEqual(relEdges(reverse));
    expect(forward.edges.some((edge) => edge.relation === 'located_in')).toBe(true);
  });

  it('respects node and edge limits', () => {
    const many = Array.from({ length: 4_500 }, (_, i) => gf(`cs-${String(i).padStart(5, '0')}`, { file: `src/f${i}.ts`, route: null }));
    const graph = extendGraphWithAudit(emptyGraph, many, [], new Map());
    expect(graph.nodes.length).toBeLessThanOrEqual(4_000);
    expect(graph.edges.length).toBeLessThanOrEqual(8_000);
  });
});

describe('Phase 7 near-duplicate detection', () => {
  it('groups genuine near duplicates deterministically without changing them', () => {
    const a = gf('cs-a', { line: 10, route: null, routeId: null });
    const b = gf('cs-b', { line: 12, route: null, routeId: null });
    const before = JSON.stringify([a, b]);
    const groups = findNearDuplicates([b, a]);
    expect(groups).toHaveLength(1);
    expect(groups[0].anchorId).toBe('cs-a');
    expect(groups[0].findingIds).toEqual(['cs-a', 'cs-b']);
    expect(findNearDuplicates([a, b])).toEqual(groups);
    expect(JSON.stringify([a, b])).toBe(before);
    expect(a.id).toBe('cs-a');
    expect(b.id).toBe('cs-b');
  });

  it('does not group unrelated findings', () => {
    const base = gf('cs-a', { line: 10, route: null, routeId: null });
    const farLine = gf('cs-b', { line: 50, route: null, routeId: null });
    const otherCategory = gf('cs-c', { line: 11, route: null, routeId: null, category: 'xss' });
    const otherFile = gf('cs-d', { line: 10, route: null, routeId: null, file: 'src/other.ts' });
    const otherRoute = gf('cs-e', { line: 11, route: 'GET /other' });
    const routed = gf('cs-f', { line: 10, route: 'GET /admin' });
    expect(findNearDuplicates([base, farLine, otherCategory, otherFile])).toEqual([]);
    expect(findNearDuplicates([routed, otherRoute])).toEqual([]);
  });
});

describe('Phase 7 prioritization', () => {
  it('breaks ties by severity, then status, then id', () => {
    const make = (id: string, severity: Severity, status: FindingStatus): AuditFinding => {
      const finding = gf(id, { severity });
      finding.status = status;
      finding.riskScore = 50;
      return finding;
    };
    const sorted = [make('cs-d', 'medium', 'candidate'), make('cs-c', 'high', 'candidate'), make('cs-b', 'high', 'verified'), make('cs-a', 'high', 'candidate')].sort(compareFindings);
    expect(sorted.map((item) => item.id)).toEqual(['cs-b', 'cs-a', 'cs-c', 'cs-d']);
  });

  it('falls back deterministically when riskScore is absent', () => {
    const items = [gf('cs-a', { severity: 'low' }), gf('cs-b', { severity: 'critical' }), gf('cs-c', { severity: 'high' })];
    const one = [...items].sort(compareFindings).map((item) => item.id);
    const two = [...items].reverse().sort(compareFindings).map((item) => item.id);
    expect(one).toEqual(two);
    expect(one[0]).toBe('cs-b');
  });
});
