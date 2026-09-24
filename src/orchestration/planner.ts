import type { InvestigationScope } from '../investigation/types.js';
import type { AuditFocus, AuditSession, CapabilityPlanEntry } from './types.js';

/** Deterministic mapping only. No model is consulted; the external AI decides what to actually investigate. */
export const FOCUS_SCOPES: Record<AuditFocus, InvestigationScope[]> = {
  general: ['general_application_security'],
  authentication: ['authentication'],
  authorization: ['authorization', 'idor_bola'],
  api_security: ['route_security', 'authentication', 'authorization'],
  input_validation: ['input_validation'],
  secrets: ['secrets_exposure'],
  route: ['route_security', 'authorization'],
  finding: ['general_application_security'],
};

export const FOCUS_FINDING_CATEGORIES: Record<AuditFocus, string[]> = {
  general: [],
  authentication: ['authentication', 'missing_authentication'],
  authorization: ['authorization', 'missing_authorization', 'idor_candidate', 'user_resource_access', 'inconsistent_authorization'],
  api_security: ['authentication', 'authorization', 'cors', 'security_configuration', 'ssrf'],
  input_validation: ['injection', 'command_injection', 'xss', 'path_traversal', 'deserialization', 'file_upload', 'ssrf'],
  secrets: ['secrets'],
  route: ['authentication', 'authorization'],
  finding: [],
};

const FOCUS_RULES: Array<[AuditFocus, RegExp]> = [
  ['secrets', /\b(secrets?|credentials?|api[ _-]?keys?|hard-?coded)\b/i],
  ['authentication', /(authenticat|login|jwt|session|password)/i],
  ['authorization', /(authoriz|access[ -]control|permission|privilege|idor|bola|role)/i],
  ['input_validation', /(input|validat|inject|xss|sanitiz|sql|deserializ)/i],
  ['api_security', /\b(api|endpoint|rest|graphql|route|cors)s?\b/i],
];

export function inferFocus(text: string): AuditFocus {
  for (const [focus, pattern] of FOCUS_RULES) if (pattern.test(text)) return focus;
  return 'general';
}

export function scopesFor(focus: AuditFocus): InvestigationScope[] {
  return [...FOCUS_SCOPES[focus]];
}

export function buildCapabilityPlan(session: AuditSession): CapabilityPlanEntry[] {
  const status = session.status;
  const done = (tool: string) => session.completedCapabilities.some((t) => t === tool);
  const analysisDone = done('run_audit_analysis');
  const active = status === 'planning' || status === 'investigating' || status === 'awaiting_verification';
  const notActive = status === 'created' ? 'Call plan_security_investigation first.' : `Not available while the audit is ${status}.`;
  const stepsAvailable = session.steps.length < session.limits.maxSteps;

  const entry = (
    tool: string,
    kind: CapabilityPlanEntry['kind'],
    purpose: string,
    required: boolean,
    completed: boolean,
    reason: string | null
  ): CapabilityPlanEntry => ({
    tool,
    kind,
    purpose,
    required,
    status: completed ? 'completed' : reason ? 'unavailable' : 'available',
    unavailableReason: completed ? null : reason,
  });

  let verificationReason: string | null = null;
  if (status !== 'awaiting_verification') verificationReason = 'Available only while awaiting_verification (after analysis produced access-control findings).';
  else if (session.hypotheses.length === 0) verificationReason = 'Record an audit hypothesis with a findingId first.';
  else if (session.verificationAttempts >= session.limits.maxVerificationRequests) verificationReason = 'Runtime verification request limit reached.';

  return [
    entry('run_audit_analysis', 'orchestrated', 'Run the existing deterministic project discovery, static scan, route discovery and access-control analysis once.', true, analysisDone, analysisDone ? null : status === 'planning' ? null : notActive),
    entry('record_audit_hypothesis', 'orchestrated', 'Record an unverified hypothesis. Hypotheses are never evidence or findings.', false, false, active ? null : notActive),
    entry('request_audit_verification', 'orchestrated', 'Ask the existing Phase 6 runtime verifier to test one hypothesis against an operator-authorized local target. Existing safety controls decide whether it runs.', false, false, verificationReason),
    entry('complete_security_audit', 'orchestrated', 'Mark the audit complete once all required deterministic work has finished.', true, status === 'completed', analysisDone && (status === 'investigating' || status === 'awaiting_verification') && stepsAvailable ? null : status === 'completed' ? null : !stepsAvailable ? 'Maximum audit steps reached.' : 'Requires finished analysis and an active audit.'),
    entry('generate_security_audit_report', 'orchestrated', 'Generate the existing Phase 8 report for a completed audit with a traceability map.', false, done('generate_security_audit_report'), status === 'completed' && (done('generate_security_audit_report') || stepsAvailable) ? null : status !== 'completed' ? 'Requires a completed audit.' : 'Maximum audit steps reached.'),
    entry('list_files, read_file, search_files, get_project_info, analyze_project, scan_project, discover_routes, analyze_access_control', 'read_only_inspection', 'Existing read-only tools. They run outside audit state and are not recorded as audit steps.', false, false, null),
    entry('propose_remediation, apply_remediation, verify_remediation, rollback_remediation', 'controlled_remediation', 'Existing Phase 9 controlled remediation. The orchestrator never edits source files itself.', false, false, status === 'completed' ? null : 'Requires a completed audit.'),
  ];
}
