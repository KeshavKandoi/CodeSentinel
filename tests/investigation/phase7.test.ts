import { beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { toolDefinitions } from '../../src/tools/registry.js';
import { getInvestigation, recordHypothesis, requestRuntimeVerification, resetInvestigationsForTests, runSecurityAnalysis, startInvestigation } from '../../src/investigation/orchestrator.js';
import type { AppConfig } from '../../src/config.js';

const FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/access-control-express', import.meta.url)));
const EMPTY_FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/generic-node', import.meta.url)));
const config: AppConfig = { projectRoot: FIXTURE, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 };

function tool(name: string) {
  const found = toolDefinitions.find((item) => item.name === name);
  if (!found) throw new Error(`missing tool ${name}`);
  return found;
}

function payload(response: { content: Array<{ text: string }> }) {
  return JSON.parse(response.content[0]!.text) as Record<string, any>;
}

beforeEach(() => resetInvestigationsForTests());

describe('Phase 7 registration and input safety', () => {
  it('registers all agent workflow tools and instructions', () => {
    expect(toolDefinitions.map((item) => item.name)).toEqual(expect.arrayContaining([
      'start_security_investigation', 'get_investigation', 'run_security_analysis',
      'record_security_hypothesis', 'request_runtime_verification', 'get_security_agent_instructions',
    ]));
  });

  it('returns structured errors for malformed input and unknown investigations', async () => {
    const malformed = await tool('start_security_investigation').handler(config, { projectPath: FIXTURE, scope: [], hypothesis: 'x' });
    expect(malformed.isError).toBe(true);
    expect(payload(malformed).error).toBe('INVALID_INPUT');
    const unknown = await tool('get_investigation').handler(config, { investigationId: 'missing' });
    expect(unknown.isError).toBe(true);
    expect(payload(unknown).error).toBe('INVESTIGATION_NOT_FOUND');
  });

  it('enforces the configured project boundary', async () => {
    const response = await tool('start_security_investigation').handler(config, {
      projectPath: '/tmp/unrelated-project', scope: ['general_application_security'], hypothesis: 'test',
    });
    expect(response.isError).toBe(true);
    expect(payload(response).error).toBe('PROJECT_BOUNDARY');
  });

  it('rejects non-four-stage analysis budgets with a clear validation error', async () => {
    const response = await tool('start_security_investigation').handler(config, {
      projectPath: FIXTURE, scope: ['authentication'], hypothesis: 'invalid budget', budget: { maxAnalysisSteps: 3 },
    });
    expect(payload(response).error).toBe('INVALID_INPUT');
    expect(payload(response).message).toContain('exactly four');
  });
});

describe('Phase 7 state machine and budgets', () => {
  it('rejects analysis before creation, duplicate analysis, and hypotheses without evidence', async () => {
    const missing = await tool('run_security_analysis').handler(config, { investigationId: 'missing' });
    expect(payload(missing).error).toBe('INVESTIGATION_NOT_FOUND');
    const started = payload(await tool('start_security_investigation').handler(config, {
      projectPath: FIXTURE, scope: ['authorization'], hypothesis: 'Find authorization flaws',
    }));
    const id = started.id as string;
    const beforeAnalysis = await tool('record_security_hypothesis').handler(config, {
      investigationId: id, title: 'No evidence', description: 'invalid', evidenceRefs: ['unknown'],
    });
    expect(payload(beforeAnalysis).error).toBe('INVALID_TRANSITION');
    const analysis = await tool('run_security_analysis').handler(config, { investigationId: id });
    expect(analysis.isError).toBe(false);
    const duplicate = await tool('run_security_analysis').handler(config, { investigationId: id });
    expect(duplicate.isError).toBe(false);
    expect(payload(duplicate).execution.analysisSteps).toBe(4);
    const noEvidence = await tool('record_security_hypothesis').handler(config, {
      investigationId: id, title: 'No evidence', description: 'invalid', evidenceRefs: ['missing-ref'],
    });
    expect(payload(noEvidence).error).toBe('HYPOTHESIS_INVALID');
  });

  it('enforces hypothesis budgets, duplicate hypotheses, and redacts returned state', async () => {
    const started = payload(await tool('start_security_investigation').handler(config, {
      projectPath: FIXTURE, scope: ['authentication'], hypothesis: 'Bounded investigation', budget: { maxHypotheses: 1 },
    }));
    const id = started.id as string;
    const analysis = payload(await tool('run_security_analysis').handler(config, { investigationId: id }));
    const evidenceRef = `project`;
    const input = { investigationId: id, title: 'Bearer token hypothesis', description: 'Bearer supersecret-token', evidenceRefs: [evidenceRef] };
    const first = await tool('record_security_hypothesis').handler(config, input);
    expect(first.isError).toBe(false);
    const second = await tool('record_security_hypothesis').handler(config, input);
    expect(payload(second).error).toBe('BUDGET_EXCEEDED');
    const state = payload(await tool('get_investigation').handler(config, { investigationId: id }));
    expect(JSON.stringify(state)).not.toContain('supersecret-token');
    expect(analysis.status).toBe('awaiting_verification');
  });

  it('rejects cross-investigation references and mismatched finding evidence', async () => {
    const first = payload(await tool('start_security_investigation').handler(config, {
      projectPath: FIXTURE, scope: ['authorization'], hypothesis: 'first',
    }));
    const second = payload(await tool('start_security_investigation').handler(config, {
      projectPath: FIXTURE, scope: ['authorization'], hypothesis: 'second',
    }));
    await tool('run_security_analysis').handler(config, { investigationId: first.id });
    const firstAnalysis = payload(await tool('get_investigation').handler(config, { investigationId: first.id }));
    const findingId = firstAnalysis.analysis.accessControl.findingIds[0];
    const foreignEvidenceId = firstAnalysis.evidence.find((e: { reference: string }) => e.reference === `accessFinding:${findingId}`).id;
    await tool('run_security_analysis').handler(config, { investigationId: second.id });
    const crossReference = await tool('record_security_hypothesis').handler(config, {
      investigationId: second.id, title: 'Cross-project evidence', description: 'invalid',
      evidenceRefs: [foreignEvidenceId],
    });
    expect(payload(crossReference).error).toBe('HYPOTHESIS_INVALID');
    const mismatch = await tool('record_security_hypothesis').handler(config, {
      investigationId: second.id, title: 'Mismatched evidence', description: 'invalid',
      findingId, evidenceRefs: ['project'],
    });
    expect(payload(mismatch).error).toBe('HYPOTHESIS_INVALID');
  });

  it('fails safely when the evidence-byte budget is exhausted', async () => {
    const started = await tool('start_security_investigation').handler(config, {
      projectPath: FIXTURE, scope: ['general_application_security'], hypothesis: 'small evidence budget',
      budget: { maxEvidenceBytes: 1_000 },
    });
    const id = payload(started).id as string;
    const analysis = await tool('run_security_analysis').handler(config, { investigationId: id });
    expect(payload(analysis).error).toBe('BUDGET_EXCEEDED');
    const state = payload(await tool('get_investigation').handler(config, { investigationId: id }));
    expect(state.status).toBe('blocked');
    expect(state.execution.evidenceBytes).toBeLessThanOrEqual(1_000);
  });

  it('serializes concurrent analysis calls for one investigation', async () => {
    const started = payload(await tool('start_security_investigation').handler(config, {
      projectPath: FIXTURE, scope: ['route_security'], hypothesis: 'concurrency',
    }));
    const results = await Promise.all([
      tool('run_security_analysis').handler(config, { investigationId: started.id }),
      tool('run_security_analysis').handler(config, { investigationId: started.id }),
    ]);
    expect(results.every((result) => result.isError === false)).toBe(true);
    const state = payload(await tool('get_investigation').handler(config, { investigationId: started.id }));
    expect(state.execution.analysisSteps).toBe(4);
    expect(state.steps.filter((step: { operation: string }) => step.operation === 'access_control_analysis')).toHaveLength(1);
  });

  it('allows exactly one concurrent hypothesis when one budget slot remains', async () => {
    const started = payload(await tool('start_security_investigation').handler(config, {
      projectPath: FIXTURE, scope: ['authorization'], hypothesis: 'hypothesis race', budget: { maxHypotheses: 1 },
    }));
    await tool('run_security_analysis').handler(config, { investigationId: started.id });
    const input = { investigationId: started.id, title: 'same hypothesis', description: 'race', evidenceRefs: ['project'] };
    const results = await Promise.all([
      tool('record_security_hypothesis').handler(config, input),
      tool('record_security_hypothesis').handler(config, input),
    ]);
    expect(results.filter((result) => !result.isError)).toHaveLength(1);
    expect(results.filter((result) => result.isError && ['DUPLICATE_OPERATION', 'BUDGET_EXCEEDED'].includes(payload(result).error))).toHaveLength(1);
  });

  it('rejects concurrent analysis and hypothesis calls until lifecycle permits the hypothesis', async () => {
    const started = payload(await tool('start_security_investigation').handler(config, {
      projectPath: FIXTURE, scope: ['authorization'], hypothesis: 'lifecycle race',
    }));
    const [analysis, hypothesis] = await Promise.all([
      tool('run_security_analysis').handler(config, { investigationId: started.id }),
      tool('record_security_hypothesis').handler(config, { investigationId: started.id, title: 'race', description: 'race', evidenceRefs: ['missing'] }),
    ]);
    expect(analysis.isError).toBe(false);
    expect(hypothesis.isError).toBe(true);
    expect(['INVALID_TRANSITION', 'HYPOTHESIS_INVALID']).toContain(payload(hypothesis).error);
  });

  it('blocks analysis when the elapsed-time budget is exceeded', async () => {
    vi.useFakeTimers();
    try {
      const started = payload(await tool('start_security_investigation').handler(config, {
        projectPath: FIXTURE, scope: ['route_security'], hypothesis: 'elapsed', budget: { maxElapsedMs: 1_000 },
      }));
      vi.advanceTimersByTime(1_001);
      const analysis = await tool('run_security_analysis').handler(config, { investigationId: started.id });
      expect(payload(analysis).error).toBe('BUDGET_EXCEEDED');
      const state = payload(await tool('get_investigation').handler(config, { investigationId: started.id }));
      expect(state.status).toBe('blocked');
    } finally {
      vi.useRealTimers();
    }
  });

  it('completes investigations with no verification-relevant findings', async () => {
    const emptyConfig = { ...config, projectRoot: EMPTY_FIXTURE };
    const started = payload(await tool('start_security_investigation').handler(emptyConfig, {
      projectPath: EMPTY_FIXTURE, scope: ['general_application_security'], hypothesis: 'no findings expected',
    }));
    const analysis = payload(await tool('run_security_analysis').handler(emptyConfig, { investigationId: started.id }));
    expect(analysis.status).toBe('completed');
    expect(analysis.findings).toHaveLength(0);
  });

  it('cleans up only terminal investigations when the bounded store reaches capacity', async () => {
    const completed = payload(await tool('start_security_investigation').handler(config, {
      projectPath: EMPTY_FIXTURE, scope: ['general_application_security'], hypothesis: 'terminal',
    }));
    await tool('run_security_analysis').handler({ ...config, projectRoot: EMPTY_FIXTURE }, { investigationId: completed.id });
    for (let index = 0; index < 99; index += 1) {
      const response = await tool('start_security_investigation').handler(config, {
        projectPath: FIXTURE, scope: ['authentication'], hypothesis: `active-${index}`,
      });
      expect(response.isError).toBe(false);
    }
    const replacement = await tool('start_security_investigation').handler(config, {
      projectPath: FIXTURE, scope: ['authentication'], hypothesis: 'replacement',
    });
    expect(replacement.isError).toBe(false);
  });

  it('returns detached snapshots even when nested objects are mutated by the caller', async () => {
    const started = startInvestigation(config, { projectPath: FIXTURE, scope: ['authorization'], hypothesis: 'snapshot' });
    if (!started.ok) throw new Error(started.error.message);
    const id = started.data.id;
    const analysis = await runSecurityAnalysis(config, id);
    if (!analysis.ok) throw new Error(analysis.error.message);
    const findingId = analysis.data.analysis?.accessControl.findingIds.find((value) => value.startsWith('CS-ACCESS-001'));
    if (!findingId) throw new Error('test fixture did not produce an access finding');
    const hypothesis = await recordHypothesis(config, { investigationId: id, title: 'snapshot hypothesis', description: 'snapshot', findingId, evidenceRefs: [`accessFinding:${findingId}`] });
    if (!hypothesis.ok) throw new Error(hypothesis.error.message);
    const runtime = await requestRuntimeVerification(config, { investigationId: id, hypothesisId: hypothesis.data.id, findingId, target: { allowedOrigin: 'http://10.0.0.4:3000' } });
    if (!runtime.ok) throw new Error(runtime.error.message);
    const snapshot = getInvestigation(id);
    if (!snapshot.ok) throw new Error(snapshot.error.message);
    snapshot.data.hypotheses[0]!.title = 'mutated';
    snapshot.data.hypotheses[0]!.evidenceRefs.push('invented');
    snapshot.data.evidence.pop();
    snapshot.data.steps.pop();
    snapshot.data.findings[0]!.title = 'mutated';
    snapshot.data.execution.operations.push('invented');
    snapshot.data.runtimeResults[hypothesis.data.id]!.summary = 'mutated';
    const later = getInvestigation(id);
    if (!later.ok) throw new Error(later.error.message);
    expect(later.data.hypotheses[0]!.title).toBe('snapshot hypothesis');
    expect(later.data.hypotheses[0]!.evidenceRefs).not.toContain('invented');
    expect(later.data.evidence.length).toBeGreaterThan(0);
    expect(later.data.steps.length).toBe(6);
    expect(later.data.findings.find((finding) => finding.findingId === findingId)!.title).not.toBe('mutated');
    expect(later.data.execution.operations).not.toContain('invented');
    expect(later.data.runtimeResults[hypothesis.data.id]!.summary).not.toBe('mutated');
  });

  it('serializes concurrent runtime requests so only one verification executes', async () => {
    const started = startInvestigation(config, { projectPath: FIXTURE, scope: ['authorization'], hypothesis: 'runtime race' });
    if (!started.ok) throw new Error(started.error.message);
    const analysis = await runSecurityAnalysis(config, started.data.id);
    if (!analysis.ok) throw new Error(analysis.error.message);
    const findingId = analysis.data.analysis?.accessControl.findingIds.find((value) => value.startsWith('CS-ACCESS-001'));
    if (!findingId) throw new Error('test fixture did not produce an access finding');
    const hypothesis = await recordHypothesis(config, { investigationId: started.data.id, title: 'runtime race', description: 'race', findingId, evidenceRefs: [`accessFinding:${findingId}`] });
    if (!hypothesis.ok) throw new Error(hypothesis.error.message);
    const input = { investigationId: started.data.id, hypothesisId: hypothesis.data.id, findingId, target: { allowedOrigin: 'http://10.0.0.4:3000' } };
    const results = await Promise.all([requestRuntimeVerification(config, input), requestRuntimeVerification(config, input)]);
    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(results.filter((result) => !result.ok && result.error.code === 'INVALID_TRANSITION')).toHaveLength(1);
    const state = getInvestigation(started.data.id);
    if (!state.ok) throw new Error(state.error.message);
    expect(state.data.execution.runtimeVerifications).toBe(1);
  });
});

describe('Phase 7 complete workflow', () => {
  it('runs start -> analysis -> hypothesis -> Phase 6 delegation -> get', async () => {
    const started = payload(await tool('start_security_investigation').handler(config, {
      projectPath: FIXTURE,
      scope: ['authentication', 'authorization', 'idor_bola', 'route_security'],
      hypothesis: 'Determine whether a sensitive administrative route lacks authentication.',
    }));
    const investigationId = started.id as string;
    const analysis = payload(await tool('run_security_analysis').handler(config, { investigationId }));
    const findingId = analysis.analysis.accessControl.findingIds.find((id: string) => id.startsWith('CS-ACCESS-001'));
    expect(findingId).toBeDefined();
    const hypothesis = payload(await tool('record_security_hypothesis').handler(config, {
      investigationId,
      title: 'Administrative route may lack authentication',
      description: 'The static access-control finding identifies an unguarded state-changing administrative route.',
      findingId,
      evidenceRefs: [`accessFinding:${findingId}`],
      severity: 'high',
      confidence: 'medium',
    }));
    const runtimeInput = {
      investigationId,
      hypothesisId: hypothesis.id,
      findingId,
      target: { allowedOrigin: 'http://10.0.0.4:3000' },
    };
    const runtime = await tool('request_runtime_verification').handler(config, runtimeInput);
    expect(runtime.isError).toBe(false);
    const completed = payload(await tool('get_investigation').handler(config, { investigationId }));
    expect(completed.status).toBe('completed');
    expect(completed.hypotheses[0].status).toBe('blocked');
    const investigatedFinding = completed.findings.find((finding: { findingId: string }) => finding.findingId === findingId);
    expect(investigatedFinding).toBeDefined();
    expect(investigatedFinding.runtimeVerificationStatus).toBe('blocked');
    expect(investigatedFinding.staticStatus).toBe('suspected');
    expect(investigatedFinding.lifecycle).not.toBe('runtime_verified');
    expect(completed.hypotheses[0].evidenceRefs.some((ref: string) => ref.startsWith('evidence-'))).toBe(true);
    expect(completed.runtimeResults[hypothesis.id].status).toBe('blocked');
    const repeated = await tool('request_runtime_verification').handler(config, runtimeInput);
    expect(payload(repeated).error).toBe('INVALID_TRANSITION');
  });

  it('refuses runtime verification without a matching evidence-backed hypothesis', async () => {
    const started = payload(await tool('start_security_investigation').handler(config, {
      projectPath: FIXTURE, scope: ['authorization'], hypothesis: 'test',
    }));
    const id = started.id as string;
    await tool('run_security_analysis').handler(config, { investigationId: id });
    const response = await tool('request_runtime_verification').handler(config, {
      investigationId: id, hypothesisId: 'missing', findingId: 'missing', target: { allowedOrigin: 'http://127.0.0.1:1' },
    });
    expect(payload(response).error).toBe('HYPOTHESIS_NOT_FOUND');
  });

  it('returns external-agent instructions without an embedded model provider', async () => {
    const response = await tool('get_security_agent_instructions').handler(config, {});
    expect(response.isError).toBe(false);
    const instructions = payload(response).instructions as string;
    expect(instructions).toContain('external AI agent');
    expect(instructions).toContain('does not contain an LLM API key');
    expect(instructions).not.toContain('OPENAI_API_KEY');
  });
});
