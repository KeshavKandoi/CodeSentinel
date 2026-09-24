import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { AppConfig } from '../config.js';
import { listFiles, readFile } from '../fs/fsOperations.js';
import { runProjectDiscovery } from '../discovery/projectDiscovery.js';
import { scanProject } from '../security/scanner.js';
import { discoverRoutes } from '../routes/engine.js';
import { analyzeAccessControl } from '../access/engine.js';
import { detachedRedacted } from '../report/redaction.js';
import { err, ok, type ToolOutcome } from '../types.js';
import { SECURITY_DOMAINS, type BaselineComparison, type DeepSecurityAuditResult, type DomainCoverage, type IntelligenceEvidence, type IntelligenceFinding, type RepositoryIndex, type SecurityDomain } from './types.js';

const MAX_FILES = 2_000;
const MAX_FILE_BYTES = 1_000_000;
const MAX_TOTAL_BYTES = 25_000_000;
const MAX_FINDINGS = 500;
const MAX_EVIDENCE = 1_000;

interface IndexedText { path: string; text: string; hash: string; language: string; }
interface DomainRule { domain: SecurityDomain; title: string; severity: IntelligenceFinding['severity']; pattern: RegExp; reason: string; remediation: string; }

const DOMAIN_RULES: DomainRule[] = [
  { domain: 'injection', title: 'Request-derived input reaches a query sink', severity: 'high', pattern: /(?:req|request|params|query|body).*?(?:query|execute|raw|findOne|sequelize|sql)/i, reason: 'The same source line contains request-derived data and a database query operation; data-flow requires review.', remediation: 'Use parameterized queries and validate request input at the boundary.' },
  { domain: 'command_execution', title: 'Request-derived input reaches a command sink', severity: 'critical', pattern: /(?:req|request|params|query|body).*?(?:exec|spawn|execFile|child_process)/i, reason: 'The same source line contains request-derived data and a process execution sink.', remediation: 'Remove shell interpretation and use a fixed executable and argument allowlist.' },
  { domain: 'path_traversal', title: 'Request-derived input reaches a filesystem path sink', severity: 'high', pattern: /(?:req|request|params|query|body).*?(?:readFile|writeFile|sendFile|unlink|rename|path\.(?:join|resolve))/i, reason: 'Request-derived data appears to influence a filesystem operation.', remediation: 'Resolve against an approved root and reject traversal and symlink escapes.' },
  { domain: 'ssrf', title: 'Request-derived input reaches an outbound HTTP sink', severity: 'high', pattern: /(?:req|request|params|query|body).*?(?:fetch|axios|http\.request|https\.request|got\s*\()/i, reason: 'Request-derived data appears to influence an outbound request destination.', remediation: 'Use an explicit origin allowlist and validate every redirect and resolved address.' },
  { domain: 'xss', title: 'Request-derived input reaches an HTML rendering sink', severity: 'high', pattern: /(?:req|request|params|query|body).*?(?:innerHTML|dangerouslySetInnerHTML|res\.send|render\s*\()/i, reason: 'Untrusted request data appears near an HTML or template output sink.', remediation: 'Use contextual output encoding and safe template APIs.' },
  { domain: 'csrf', title: 'State-changing route lacks an obvious CSRF control', severity: 'medium', pattern: /(?:post|put|patch|delete).*?(?:router|app)\.(?:post|put|patch|delete)\s*\(/i, reason: 'A state-changing route was indexed; CSRF protection could not be established from this local pattern.', remediation: 'Require same-site protections and an explicit CSRF token for cookie-authenticated state changes.' },
  { domain: 'file_upload', title: 'Upload handling lacks a visible bounded validation control', severity: 'medium', pattern: /(?:multer|upload|fileUpload|multipart)/i, reason: 'An upload-related construct was found; size, type, and storage safety require review.', remediation: 'Enforce size and MIME limits, randomize names, and store uploads outside executable paths.' },
  { domain: 'deserialization', title: 'Unsafe deserialization or evaluation sink', severity: 'high', pattern: /(?:unserialize|deserialize|yaml\.load|eval\s*\(|vm\.run|Function\s*\()/i, reason: 'A deserialization or code-evaluation sink was detected.', remediation: 'Use a safe parser with a schema and reject executable serialization formats.' },
  { domain: 'prototype_pollution', title: 'Dynamic object key assignment may affect object prototypes', severity: 'medium', pattern: /(?:__proto__|constructor\s*\[|prototype\s*\[|Object\.assign\s*\()/i, reason: 'A prototype-sensitive property or merge operation was detected.', remediation: 'Reject prototype keys and use safe object construction with schema validation.' },
  { domain: 'insecure_redirects', title: 'Potentially user-controlled redirect', severity: 'medium', pattern: /(?:redirect|location\.href|window\.location).*?(?:req|request|query|params|url)/i, reason: 'Redirect behavior appears near request-derived URL data.', remediation: 'Allow only relative paths or an explicit destination allowlist.' },
  { domain: 'cors', title: 'Permissive cross-origin policy', severity: 'medium', pattern: /(?:cors|Access-Control-Allow-Origin|origin\s*:\s*(?:true|['"]\*['"]))/i, reason: 'A permissive CORS construct was detected.', remediation: 'Use an explicit trusted-origin allowlist and avoid credentialed wildcard access.' },
  { domain: 'security_headers', title: 'Security header configuration requires review', severity: 'low', pattern: /(?:helmet\s*\(\s*false|x-powered-by|Content-Security-Policy|Strict-Transport-Security)/i, reason: 'Security-header configuration was detected and requires deterministic configuration review.', remediation: 'Enable framework security headers and remove identifying response headers.' },
  { domain: 'session_cookies', title: 'Session or cookie security configuration requires review', severity: 'medium', pattern: /(?:cookie|session).*?(?:secure\s*:\s*false|httpOnly\s*:\s*false|sameSite\s*:\s*['"]?none)/i, reason: 'A session/cookie option appears to weaken transport or script isolation.', remediation: 'Use Secure, HttpOnly, and an appropriate SameSite policy.' },
  { domain: 'jwt', title: 'JWT verification configuration requires review', severity: 'high', pattern: /(?:jwt|jsonwebtoken).*?(?:decode\s*\(|none|algorithm|verify)/i, reason: 'JWT handling was detected; algorithm and signature verification require review.', remediation: 'Pin accepted algorithms, verify signatures, issuer, audience, and expiration.' },
  { domain: 'cryptography', title: 'Weak or disabled cryptographic protection', severity: 'medium', pattern: /(?:md5|sha1|rejectUnauthorized\s*:\s*false|Math\.random\s*\()/i, reason: 'A weak hash, insecure randomness, or disabled certificate verification was detected.', remediation: 'Use modern cryptography, CSPRNGs, and certificate verification.' },
  { domain: 'secrets', title: 'Hardcoded secret-like value', severity: 'high', pattern: /(?:api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]\s*['"][^'"]{8,}['"]/i, reason: 'A credential-like identifier is assigned a nontrivial literal value.', remediation: 'Remove the value, rotate it, and use an approved secret manager.' },
  { domain: 'environment_configuration', title: 'Sensitive environment/configuration exposure', severity: 'high', pattern: /(?:\.env|process\.env|config\.(?:json|ya?ml)|credentials)/i, reason: 'Sensitive configuration material or environment access was detected; exposure and trust boundaries require review.', remediation: 'Keep sensitive configuration out of source and restrict its propagation.' },
  { domain: 'npm_scripts', title: 'Install or lifecycle script requires supply-chain review', severity: 'medium', pattern: /"(?:preinstall|install|postinstall|prepare)"\s*:/i, reason: 'A package lifecycle script executes during installation.', remediation: 'Review and minimize lifecycle scripts; pin trusted dependencies and use lockfile integrity.' },
  { domain: 'docker', title: 'Container configuration requires hardening review', severity: 'medium', pattern: /(?:Dockerfile|docker-compose|privileged\s*:\s*true|USER\s+root)/i, reason: 'Container configuration was detected; privilege, secrets, and network boundaries require review.', remediation: 'Use a non-root user, minimal images, pinned bases, and least-privilege capabilities.' },
  { domain: 'ci_cd', title: 'CI workflow requires trust-boundary review', severity: 'medium', pattern: /(?:\.github\/workflows|pull_request_target|secrets\.[A-Za-z_]|actions\/checkout)/i, reason: 'CI automation or secret use was detected; untrusted event inputs require review.', remediation: 'Pin actions, isolate untrusted pull requests, and minimize token permissions.' },
  { domain: 'database', title: 'Database operation requires authorization/data-flow review', severity: 'medium', pattern: /(?:sequelize|mongoose|prisma|knex|typeorm|\.query\s*\(|SELECT\s|UPDATE\s|DELETE\s)/i, reason: 'A database operation was indexed; parameterization and authorization boundaries require review.', remediation: 'Parameterize queries and enforce object-level authorization before database access.' },
  { domain: 'api_security', title: 'API boundary requires validation/rate-limit review', severity: 'low', pattern: /(?:router|app)\.(?:get|post|put|patch|delete)\s*\(/i, reason: 'An API route was indexed; input validation, rate limiting, and error handling require review.', remediation: 'Validate schemas, bound payloads, rate-limit abuse, and avoid leaking internal errors.' },
  { domain: 'websocket', title: 'WebSocket boundary requires authentication review', severity: 'medium', pattern: /(?:WebSocket|socket\.io|ws\.on|io\.on)/i, reason: 'A WebSocket construct was indexed; connection and message authorization require review.', remediation: 'Authenticate connections and authorize every sensitive message/action.' },
  { domain: 'graphql', title: 'GraphQL boundary requires authorization and complexity controls', severity: 'medium', pattern: /(?:graphql|ApolloServer|GraphQLSchema|resolver)/i, reason: 'GraphQL constructs were indexed; resolver authorization and query complexity require review.', remediation: 'Authorize resolvers, bound depth/complexity, and disable unsafe introspection where appropriate.' },
  { domain: 'ai_mcp', title: 'AI/agent/MCP trust boundary requires instruction and tool review', severity: 'medium', pattern: /(?:MCP|Model Context Protocol|prompt|tool\s+call|system\s+instruction|agent)/i, reason: 'Agent/tooling constructs were indexed; repository instructions and tool results are untrusted input.', remediation: 'Use explicit capability allowlists, isolate instructions from authority, and redact tool results.' },
];

const hash = (value: string | Buffer): string => crypto.createHash('sha256').update(value).digest('hex');
const languageFor = (file: string): string => path.extname(file).toLowerCase().replace('.', '') || 'text';
const stableId = (...parts: string[]): string => `deep-${hash(parts.join('|')).slice(0, 24)}`;
const redactLine = (line: string): string => line.replace(/(api[_-]?key|secret|password|token|credential)\s*([:=])\s*(['"]?)[^'"\s,;]+/gi, '$1$2 [REDACTED]');
const domainForCategory = (category: string): SecurityDomain => {
  const normalized = category.toLowerCase();
  if (normalized.includes('authentication')) return 'authentication';
  if (normalized.includes('authorization') || normalized.includes('idor') || normalized.includes('ownership')) return 'authorization';
  if (normalized.includes('secret')) return 'secrets';
  if (normalized.includes('dependency')) return 'dependency_supply_chain';
  return 'api_security';
};

function readIndexedFiles(config: AppConfig, profile: ReturnType<typeof runProjectDiscovery>, maxFiles = MAX_FILES): { texts: IndexedText[]; skipped: number; totalBytes: number } {
  const cap = Math.min(Math.max(1, maxFiles), MAX_FILES);
  const listed = listFiles(config, { dirPath: '.', recursive: true, maxResults: cap });
  const paths = listed.ok ? listed.data.filter((item) => item.type === 'file').map((item) => item.path) : [];
  for (const sensitive of [...profile.envFiles, ...profile.configFiles]) if (!paths.includes(sensitive)) paths.push(sensitive);
  const texts: IndexedText[] = [];
  let skipped = 0;
  let totalBytes = 0;
  for (const filePath of paths.sort()) {
    if (texts.length >= cap || totalBytes >= MAX_TOTAL_BYTES) { skipped++; continue; }
    const result = readFile(config, { filePath, maxBytes: MAX_FILE_BYTES, allowSensitive: true });
    if (!result.ok || result.data.truncated) { skipped++; continue; }
    const contentHash = hash(result.data.content);
    texts.push({ path: filePath, text: result.data.content, hash: contentHash, language: languageFor(filePath) });
    totalBytes += Buffer.byteLength(result.data.content, 'utf8');
  }
  return { texts, skipped, totalBytes };
}

function buildIndex(texts: IndexedText[], skipped: number): RepositoryIndex {
  const files = texts.map((item) => ({ path: item.path, sizeBytes: Buffer.byteLength(item.text), contentHash: item.hash, language: item.language, analyzed: true }));
  const all = texts.map((item) => item.text).join('\n');
  return {
    files, symbols: (all.match(/\b(?:class|function|def|interface|type|const|let|var)\s+[A-Za-z_$][\w$]*/g) ?? []).length,
    imports: (all.match(/\b(?:import|require\s*\(|from\s+)/g) ?? []).length, exports: (all.match(/\bexport\b|module\.exports/g) ?? []).length,
    routes: (all.match(/(?:router|app)\.(?:get|post|put|patch|delete|use)\s*\(/gi) ?? []).length,
    middleware: (all.match(/middleware|use\s*\(/gi) ?? []).length, databaseOperations: (all.match(/(?:query|sequelize|mongoose|prisma|knex|typeorm)/gi) ?? []).length,
    externalCalls: (all.match(/(?:fetch|axios|http\.request|https\.request|WebSocket)/gi) ?? []).length, commandSinks: (all.match(/(?:exec|spawn|child_process)/gi) ?? []).length,
    filesystemSinks: (all.match(/(?:readFile|writeFile|unlink|rename|sendFile)/gi) ?? []).length, authenticationGuards: (all.match(/(?:auth|authenticate|passport|jwt|session|login)/gi) ?? []).length,
    authorizationChecks: (all.match(/(?:authorize|permission|role|isAdmin|owner|acl)/gi) ?? []).length, secretSignals: (all.match(/(?:api[_-]?key|secret|password|token|credential)/gi) ?? []).length,
    packageDependencies: (all.match(/(?:dependencies|devDependencies|requirements|Cargo\.toml)/gi) ?? []).length,
    ciWorkflows: texts.filter((item) => item.path.startsWith('.github/workflows/')).length, dockerFiles: texts.filter((item) => /(?:Dockerfile|docker-compose)/i.test(item.path)).length,
    filesSkipped: skipped, coverageLimitations: ['AST-level symbol and data-flow resolution is not available for every language; line evidence is reported as heuristic where parsing is unsupported.'],
  };
}

function addEvidence(evidence: IntelligenceEvidence[], item: Omit<IntelligenceEvidence, 'id'>): string {
  if (evidence.length >= MAX_EVIDENCE) return '';
  const id = stableId(item.domain, item.sourceRef, item.contentHash, String(item.line));
  if (!evidence.some((entry) => entry.id === id)) evidence.push({ id, ...item });
  return id;
}

function addFinding(findings: IntelligenceFinding[], evidence: IntelligenceEvidence[], item: Omit<IntelligenceFinding, 'id' | 'evidenceIds' | 'sourceRefs' | 'convergence' | 'signals'>, refs: string[], sourceRefs: string[], signals: string[]): void {
  if (findings.length >= MAX_FINDINGS || refs.length === 0) return;
  const id = stableId(item.domain, ...sourceRefs, ...refs);
  if (findings.some((finding) => finding.id === id)) return;
  findings.push({ ...item, id, evidenceIds: refs, sourceRefs, signals, convergence: Math.min(1, signals.length / 3) });
}

function markdown(result: Omit<DeepSecurityAuditResult, 'markdown'>): string {
  const lines = [`# CodeSentinel Deep Security Audit`, '', `Project: ${result.project.name ?? 'unnamed'} (${result.project.ecosystem})`, '', '## Executive Summary', '', `${result.findings.length} evidence-backed candidate(s) were identified. Static candidates are not confirmed vulnerabilities without deterministic runtime proof.`, '', '## Domain Coverage', '', '| Domain | Status | Findings |', '|---|---|---:|'];
  for (const coverage of result.domainCoverage) lines.push(`| ${coverage.domain} | ${coverage.status} | ${coverage.findings} |`);
  lines.push('', '## Findings', '');
  for (const finding of result.findings) lines.push(`### ${finding.title} (${finding.severity})\n\n- Domain: ${finding.domain}\n- Status: ${finding.status}\n- Confidence: ${finding.confidence}\n- Convergence: ${finding.convergence.toFixed(2)}\n- Evidence: ${finding.evidenceIds.join(', ')}`);
  lines.push('', '## Limitations', '', ...result.limitations.map((item) => `- ${item}`));
  return lines.join('\n').slice(0, 200_000);
}

function compareBaseline(findings: IntelligenceFinding[], baselineText: string | null): BaselineComparison {
  if (!baselineText) return { supplied: false, newFindings: [], resolvedFindings: [], unchangedFindings: [], changedEvidence: [], limitation: null };
  try {
    const parsed = JSON.parse(baselineText) as { findings?: Array<{ id?: string; evidenceIds?: string[] }> };
    const previous = new Map((parsed.findings ?? []).filter((item) => typeof item.id === 'string').map((item) => [item.id!, item.evidenceIds ?? []]));
    const current = new Map(findings.map((item) => [item.id, item.evidenceIds]));
    return { supplied: true, newFindings: [...current.keys()].filter((id) => !previous.has(id)), resolvedFindings: [...previous.keys()].filter((id) => !current.has(id)), unchangedFindings: [...current.keys()].filter((id) => previous.has(id) && JSON.stringify(previous.get(id)) === JSON.stringify(current.get(id))), changedEvidence: [...current.keys()].filter((id) => previous.has(id) && JSON.stringify(previous.get(id)) !== JSON.stringify(current.get(id))), limitation: 'Baseline comparison is limited to stable local finding and evidence IDs; CVE history is not consulted.' };
  } catch {
    return { supplied: true, newFindings: [], resolvedFindings: [], unchangedFindings: [], changedEvidence: [], limitation: 'The supplied baseline was invalid JSON and was not used.' };
  }
}

type DeepAuditBase = Omit<DeepSecurityAuditResult, 'markdown' | 'integrity'>;
function validateIntegrity(result: DeepAuditBase): DeepSecurityAuditResult['integrity'] {
  const evidenceIds = new Set(result.evidence.map((item) => item.id));
  const invalidReferences = result.findings.flatMap((finding) => finding.evidenceIds.filter((id) => !evidenceIds.has(id)).map((id) => `${finding.id}:${id}`));
  const serialized = JSON.stringify(result);
  return { valid: invalidReferences.length === 0 && !/(Bearer\s+\w+|AKIA[0-9A-Z]{16})/i.test(serialized), checkedFindings: result.findings.length, invalidReferences, redactionPassed: !/(Bearer\s+\w+|AKIA[0-9A-Z]{16})/i.test(serialized) };
}

export async function runDeepSecurityAudit(config: AppConfig, options: { baselinePath?: string; maxFiles?: number } = {}): Promise<ToolOutcome<DeepSecurityAuditResult>> {
  const profile = runProjectDiscovery(config.projectRoot);
  const indexed = readIndexedFiles(config, profile, options.maxFiles);
  const repositoryIndex = buildIndex(indexed.texts, indexed.skipped);
  const evidence: IntelligenceEvidence[] = [];
  const findings: IntelligenceFinding[] = [];
  const staticResult = await scanProject(config);
  const routesResult = discoverRoutes(config);
  const accessResult = routesResult.ok ? analyzeAccessControl(config, routesResult.data.entries) : null;
  if (staticResult.ok) for (const finding of staticResult.data.findings) {
    const domain = domainForCategory(finding.category);
    const ref = addEvidence(evidence, { domain, kind: 'static_scan', sourceRef: finding.id, file: finding.file ?? '', line: finding.line ?? null, detail: finding.evidence[0]?.reason ?? finding.title, contentHash: hash(JSON.stringify(finding.evidence)) });
    addFinding(findings, evidence, { title: finding.title, domain, severity: finding.severity, confidence: finding.confidence, status: 'static_candidate', description: finding.description, remediation: finding.remediation }, [ref], finding.file ? [finding.file] : [], ['static_scan']);
  }
  if (accessResult) for (const finding of accessResult.findings) {
    const domain: SecurityDomain = finding.candidateType === 'idor_candidate' || finding.candidateType === 'user_resource_access' ? 'idor_bola' : finding.candidateType === 'missing_authentication' ? 'authentication' : 'authorization';
    const ref = addEvidence(evidence, { domain, kind: 'access_control', sourceRef: finding.id, file: finding.file, line: finding.line, detail: finding.description, contentHash: hash(JSON.stringify(finding.evidence)) });
    addFinding(findings, evidence, { title: finding.title, domain, severity: finding.severity, confidence: finding.confidence, status: 'static_candidate', description: finding.description, remediation: 'Add and verify the appropriate authentication, authorization, or ownership control.' }, [ref], [finding.file], ['access_control']);
  }
  for (const item of indexed.texts) {
    const lines = item.text.split('\n');
    for (let lineNo = 0; lineNo < lines.length; lineNo++) {
      const line = lines[lineNo] ?? '';
      for (const rule of DOMAIN_RULES) if (rule.pattern.test(line)) {
        const detail = redactLine(line.trim()).slice(0, 300);
        const ref = addEvidence(evidence, { domain: rule.domain, kind: 'source', sourceRef: `${item.path}:${lineNo + 1}`, file: item.path, line: lineNo + 1, detail, contentHash: item.hash });
        addFinding(findings, evidence, { title: rule.title, domain: rule.domain, severity: rule.severity, confidence: 'low', status: 'static_candidate', description: rule.reason, remediation: rule.remediation }, [ref], [item.path], ['source_pattern']);
      }
    }
  }
  findings.sort((a, b) => a.domain.localeCompare(b.domain) || a.severity.localeCompare(b.severity) || a.id.localeCompare(b.id));
  const domainCoverage: DomainCoverage[] = SECURITY_DOMAINS.map((domain) => {
    const domainFindings = findings.filter((finding) => finding.domain === domain).length;
    const rules = DOMAIN_RULES.filter((rule) => rule.domain === domain).length;
    return { domain, status: domainFindings > 0 ? 'findings' : rules > 0 ? 'passed' : 'unsupported', findings: domainFindings, filesConsidered: indexed.texts.length, rulesExecuted: rules, limitation: rules > 0 ? 'Deterministic local pattern coverage; data-flow and framework-specific semantics may require review.' : 'No safe detector is implemented for this domain in the current repository.' };
  });
  let baselineText: string | null = null;
  if (options.baselinePath) {
    const baseline = readFile(config, { filePath: options.baselinePath, maxBytes: 2_000_000 });
    if (!baseline.ok) return baseline;
    baselineText = baseline.data.content;
  }
  const baseline = compareBaseline(findings, baselineText);
  const base = { auditId: stableId(config.projectRoot, ...indexed.texts.map((item) => `${item.path}:${item.hash}`)), project: { name: profile.projectName, ecosystem: profile.ecosystem, root: '[CONFIGURED_PROJECT_ROOT]' }, repositoryIndex, domainCoverage, findings: findings.slice(0, MAX_FINDINGS), evidence: evidence.slice(0, MAX_EVIDENCE), baseline, coverage: { filesAnalyzed: indexed.texts.length, filesSkipped: indexed.skipped, routesDiscovered: routesResult.ok ? routesResult.data.entries.length : 0, accessFindings: accessResult?.findings.length ?? 0, staticFindings: staticResult.ok ? staticResult.data.findings.length : 0, runtimeChecksAttempted: 0, runtimeChecksBlocked: 0, runtimeChecksInconclusive: 0, evidenceItems: evidence.length }, limitations: [...repositoryIndex.coverageLimitations, 'No external vulnerability database or external target was contacted.', 'Runtime verification is not automatically performed by this read-only audit; use the existing Phase 6 workflow for an explicitly authorized local target.'] };
  const integrity = validateIntegrity(base);
  if (!integrity.valid) return err('REPORT_INVALID', `Deep audit integrity validation failed: ${integrity.invalidReferences.join(', ') || 'sensitive material detected'}.`);
  const result = { ...base, integrity, markdown: '' };
  result.markdown = markdown(result);
  return ok(detachedRedacted(result));
}
