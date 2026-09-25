import type { DependencyInfo } from '../../discovery/types.js';
import type { SecurityFinding, SecurityRule, SecurityScanContext } from '../types.js';
import {
  codeLineIsExecutable,
  contextFor,
  hasDynamicExpression,
  hasTaintedInput,
  isDocumentationFile,
  isIgnoredPath,
  isSourceFile,
  lineAt,
  looksLikePlaceholder,
  makeFinding,
} from '../utils.js';

type CandidatePredicate = (line: string, match: { path: string; line: number; preview: string }, content: string) => boolean;

function ruleBase(rule: Omit<SecurityRule, 'run'>): Omit<SecurityRule, 'run'> {
  return rule;
}

function isStringOnlyAssignment(line: string): boolean {
  return /^\s*(const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*['"`]/.test(line);
}

function makeSearchRule(meta: Omit<SecurityRule, 'run'>, query: string, predicate: CandidatePredicate): SecurityRule {
  return {
    ...meta,
    async run(context) {
      const findings: SecurityFinding[] = [];
      const matches = await context.search(query, { isRegex: true, caseSensitive: false, maxResults: 10_000 });
      for (const match of matches) {
        if (isIgnoredPath(match.path) || !isSourceFile(match.path)) continue;
        const file = await context.readFile(match.path);
        if (!file) continue;
        const line = lineAt(file.content, match.line);
        if (!codeLineIsExecutable(line)) continue;
        if (!predicate(line, match, file.content)) continue;
        findings.push(makeFinding(meta as SecurityRule, {
          file: match.path,
          line: match.line,
          column: match.column,
          matchedText: line.trim().slice(0, 240),
          context: contextFor(file.content, match.line),
          reason: meta.evidenceRequirements,
        }));
      }
      return findings;
    },
  };
}

const hardcodedSecrets = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-001',
    category: 'secrets',
    title: 'Hardcoded secret or credential',
    description: 'A source file appears to assign a credential-like name to a literal secret value.',
    severity: 'high',
    confidence: 'medium',
    evidenceRequirements: 'Credential-like identifier assigned to a non-placeholder literal value in executable source.',
    remediation: 'Move secrets to a secret manager or environment variable, rotate exposed values, and avoid committing credentials.',
    falsePositiveGuidance: 'Placeholder, test-only, or non-secret constants can be marked false positive after confirming no real credential value is present.',
    languages: ['node'],
  }),
  String.raw`\b(api[_-]?key|secret|password|passwd|pwd|token|private[_-]?key|client[_-]?secret|access[_-]?key)\b\s*[:=]`,
  (line) => {
    if (/process\.env\b/.test(line)) return false;
    const match = /(?:api[_-]?key|secret|password|passwd|pwd|token|private[_-]?key|client[_-]?secret|access[_-]?key)\b\s*[:=]\s*['"`]([^'"`]{8,})['"`]/i.exec(line);
    if (!match) return false;
    return !looksLikePlaceholder(match[1]);
  }
);

const sqlNoSqlInjection = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-002',
    category: 'injection',
    title: 'SQL or NoSQL injection indicator',
    description: 'A database query appears to combine user-controlled request data with a raw query or operator-sensitive expression.',
    severity: 'high',
    confidence: 'medium',
    evidenceRequirements: 'Database query sink with request-derived input and string concatenation, template interpolation, raw query, or MongoDB operator usage.',
    remediation: 'Use parameterized queries or ORM bind variables, validate request input, and avoid passing request objects directly into query filters.',
    falsePositiveGuidance: 'False positives are possible when the request value is strictly validated or converted before the shown query.',
    languages: ['node'],
  }),
  String.raw`(\.query\s*\(|\$queryRaw|queryRawUnsafe|\.aggregate\s*\(|\.find(?:One)?\s*\(|\$where|where\s*:)`,
  (line) => {
    if (isStringOnlyAssignment(line)) return false;
    const databaseSink = /(\.query\s*\(|\$queryRaw|queryRawUnsafe|\.aggregate\s*\(|\.find(?:One)?\s*\(|\$where|where\s*:)/i.test(line);
    if (!databaseSink) return false;
    if (/\$where|queryRawUnsafe/i.test(line) && hasTaintedInput(line)) return true;
    if (/\.find(?:One)?\s*\(/.test(line) && /\.\.\.\s*req\.|{\s*req\.(body|query|params)|\(\s*req\.(body|query|params)/.test(line)) return true;
    return hasTaintedInput(line) && hasDynamicExpression(line);
  }
);

const commandInjection = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-003',
    category: 'command_injection',
    title: 'Command injection indicator',
    description: 'A command execution API appears to receive request-controlled or dynamically assembled command text.',
    severity: 'critical',
    confidence: 'medium',
    evidenceRequirements: 'exec/spawn-style command sink with request-derived input or dynamic command construction.',
    remediation: 'Avoid shell execution for request input; use fixed command arrays, allowlisted arguments, and shell:false.',
    falsePositiveGuidance: 'A finding may be false positive if the argument is selected from a strict allowlist before this call.',
    languages: ['node'],
  }),
  String.raw`\b(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(`,
  (line) => !isStringOnlyAssignment(line) && (/\b(exec|execSync)\s*\(/.test(line) ? hasTaintedInput(line) || hasDynamicExpression(line) : hasTaintedInput(line))
);

const pathTraversal = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-004',
    category: 'path_traversal',
    title: 'Path traversal indicator',
    description: 'A filesystem or response-file API appears to use request-controlled path data.',
    severity: 'high',
    confidence: 'medium',
    evidenceRequirements: 'Filesystem path sink with request-derived path/name input.',
    remediation: 'Resolve paths against a fixed root, normalize and verify containment, and use allowlisted filenames or IDs.',
    falsePositiveGuidance: 'This can be false positive if a centralized path guard has already validated and confined the request value.',
    languages: ['node'],
  }),
  String.raw`(readFile|writeFile|createReadStream|sendFile|download|unlink|rename|mkdir|path\.join|path\.resolve)\s*\(`,
  (line) => !isStringOnlyAssignment(line) && hasTaintedInput(line)
);

const ssrf = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-005',
    category: 'ssrf',
    title: 'SSRF indicator',
    description: 'An outbound HTTP request appears to use a URL or hostname influenced by request data.',
    severity: 'high',
    confidence: 'medium',
    evidenceRequirements: 'HTTP client sink with request-derived URL, host, or path input.',
    remediation: 'Use an allowlist of destinations, block private/link-local ranges, and avoid constructing outbound URLs directly from requests.',
    falsePositiveGuidance: 'May be false positive when the URL has been canonicalized and checked against a strict destination allowlist.',
    languages: ['node'],
  }),
  String.raw`\b(fetch|axios\.|http\.request|https\.request|got\(|request\()\b`,
  (line) => !isStringOnlyAssignment(line) && hasTaintedInput(line)
);

const xss = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-006',
    category: 'xss',
    title: 'Cross-site scripting indicator',
    description: 'Request-controlled data appears to be written into an HTML/DOM sink without an obvious escaping boundary.',
    severity: 'high',
    confidence: 'medium',
    evidenceRequirements: 'HTML/DOM response sink with request-derived input or React dangerouslySetInnerHTML.',
    remediation: 'Use framework escaping, context-aware output encoding, and sanitize trusted HTML with a maintained sanitizer.',
    falsePositiveGuidance: 'A finding may be false positive if the data is sanitized immediately before the shown sink.',
    languages: ['node'],
  }),
  String.raw`(res\.send|res\.write|dangerouslySetInnerHTML|innerHTML|document\.write)`,
  (line) => {
    if (isStringOnlyAssignment(line)) return false;
    if (/dangerouslySetInnerHTML/.test(line)) return true;
    return /(res\.(send|write)|document\.write|innerHTML)\s*.*req\./.test(line);
  }
);

const openRedirect = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-015',
    category: 'open_redirect',
    title: 'Open redirect indicator',
    description: 'A redirect destination appears to be taken directly from request-controlled input.',
    severity: 'medium',
    confidence: 'medium',
    evidenceRequirements: 'Redirect sink receives request-controlled URL data without an obvious same-origin or allowlist check.',
    remediation: 'Allow only relative paths or destinations from an explicit origin allowlist.',
    falsePositiveGuidance: 'A finding may be false positive when the destination is validated by a helper or strict allowlist before redirecting.',
    languages: ['node'],
  }),
  String.raw`\b(?:res|reply)\.redirect\s*\(`,
  (line) => /\b(?:res|reply)\.redirect\s*\(\s*(?:String\s*\(\s*)?(?:req\.(?:query|params|body)|request\.)/i.test(line)
);

const insecureCors = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-007',
    category: 'cors',
    title: 'Insecure CORS configuration',
    description: 'CORS appears to allow arbitrary origins or wildcard browser access.',
    severity: 'medium',
    confidence: 'high',
    evidenceRequirements: 'cors or Access-Control-Allow-Origin configured with wildcard, origin:true, or reflected request origin.',
    remediation: 'Replace wildcard/reflected origins with an explicit allowlist and avoid credentials with broad origins.',
    falsePositiveGuidance: 'Wildcard CORS can be acceptable for deliberately public, credential-free APIs.',
    languages: ['node'],
  }),
  String.raw`(cors\s*\(|Access-Control-Allow-Origin|origin\s*:)`,
  (line) => !isStringOnlyAssignment(line) && /Access-Control-Allow-Origin['"`]?\s*,\s*['"`]\*|origin\s*:\s*(true|['"`]\*)|origin\s*:\s*req\./i.test(line)
);

const weakAuthentication = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-008',
    category: 'authentication',
    title: 'Missing or weak authentication indicator',
    description: 'A sensitive-looking route appears to lack authentication middleware, or authentication is explicitly bypassed.',
    severity: 'medium',
    confidence: 'low',
    evidenceRequirements: 'Sensitive route or explicit auth bypass without an auth middleware/reference on the route declaration line.',
    remediation: 'Require authentication middleware on sensitive routes and remove temporary bypasses before release.',
    falsePositiveGuidance: 'Route-level findings are often false positive if authentication is enforced globally or by upstream middleware.',
    languages: ['node'],
  }),
  String.raw`(app|router)\.(get|post|put|patch|delete)\s*\(|auth\s*:\s*false|skipAuth|disableAuth`,
  (line) => {
    if (isStringOnlyAssignment(line)) return false;
    if (/auth\s*:\s*false|skipAuth|disableAuth/i.test(line)) return true;
    if (!/['"`]\/[^'"`]*(admin|account|user|profile|settings|billing|private)/i.test(line)) return false;
    return !/(auth|authenticate|isAuthenticated|requireUser|requireAuth|passport|jwt)/i.test(line);
  }
);

const brokenAuthorization = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-009',
    category: 'authorization',
    title: 'Broken object authorization indicator',
    description: 'A route appears to access or mutate an object by request parameter without an obvious ownership/role check.',
    severity: 'high',
    confidence: 'low',
    evidenceRequirements: 'Object lookup/update/delete using req.params.id without an adjacent visible user/role/owner check.',
    remediation: 'Check the authenticated principal owns the object or has an appropriate role before returning or mutating it.',
    falsePositiveGuidance: 'May be false positive when authorization is enforced in middleware, model hooks, or service layers not visible on the matched line.',
    languages: ['node'],
  }),
  String.raw`(findById|findOneAndUpdate|findByIdAndUpdate|findByIdAndDelete|deleteOne|updateOne)\s*\(`,
  (line, _match, content) => {
    if (isStringOnlyAssignment(line) || !/req\.params\.(id|userId|accountId|projectId)/.test(line)) return false;
    const lines = content.split('\n');
    const block = lines.slice(Math.max(0, _match.line - 4), Math.min(lines.length, _match.line + 4)).join('\n').toLowerCase();
    return !/(req\.user|session\.user|owner|role|authorize|canaccess|permission)/.test(block);
  }
);

const unsafeUploads = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-010',
    category: 'file_upload',
    title: 'Unsafe file upload indicator',
    description: 'File upload middleware appears to accept uploads without visible file type or size controls.',
    severity: 'medium',
    confidence: 'medium',
    evidenceRequirements: 'multer/fileUpload/upload middleware without limits or fileFilter on the same configuration statement.',
    remediation: 'Enforce file size limits, extension/MIME validation, random storage names, and store uploads outside executable paths.',
    falsePositiveGuidance: 'Can be false positive if upload validation is applied in a wrapper or later middleware.',
    languages: ['node'],
  }),
  String.raw`(multer\s*\(|fileUpload\s*\()`,
  (line, match, content) => {
    if (isStringOnlyAssignment(line)) return false;
    const lines = content.split('\n');
    const block = lines.slice(match.line - 1, Math.min(lines.length, match.line + 8)).join('\n');
    return !/(limits|fileFilter|mime|mimetype|allowed|validate)/i.test(block);
  }
);

const dangerousDeserialization = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-011',
    category: 'deserialization',
    title: 'Dangerous deserialization indicator',
    description: 'Untrusted data appears to be passed to a deserialization or code-evaluation API.',
    severity: 'critical',
    confidence: 'medium',
    evidenceRequirements: 'deserialize/unserialize/eval/vm/yaml load style sink with request-derived input.',
    remediation: 'Avoid unsafe deserialization for untrusted input; use JSON schema validation and safe parsers without code execution semantics.',
    falsePositiveGuidance: 'May be false positive if the request body has been cryptographically authenticated and strictly validated before the call.',
    languages: ['node'],
  }),
  String.raw`(unserialize|deserialize|eval\s*\(|new Function|vm\.runIn|yaml\.load|YAML\.parse|JSON\.parse)\s*\(`,
  (line) => {
    if (isStringOnlyAssignment(line)) return false;
    if (/JSON\.parse/.test(line) && !hasTaintedInput(line)) return false;
    return hasTaintedInput(line) || /(eval\s*\(|new Function|unserialize|deserialize)/.test(line);
  }
);

const insecureConfiguration = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-012',
    category: 'security_configuration',
    title: 'Insecure security configuration',
    description: 'Security-sensitive runtime or framework configuration appears to disable protections.',
    severity: 'medium',
    confidence: 'high',
    evidenceRequirements: 'Known insecure configuration literal such as TLS verification disabled, secure cookies disabled, or Helmet disabled.',
    remediation: 'Enable secure defaults, require TLS verification, set secure cookies in production, and document any intentional exceptions.',
    falsePositiveGuidance: 'Local development-only configuration can be false positive if it is unreachable in production.',
    languages: ['node'],
  }),
  String.raw`(NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized|secure\s*:|helmet\s*\(|x-powered-by|ignoreExpiration)`,
  (line) => !isStringOnlyAssignment(line) && /NODE_TLS_REJECT_UNAUTHORIZED['"`]?\s*[,=]\s*['"`]?0|rejectUnauthorized\s*:\s*false|secure\s*:\s*false|helmet\s*\(\s*false\s*\)|x-powered-by['"`]?\s*,\s*true|ignoreExpiration\s*:\s*true/i.test(line)
);

const exposedConfigSecrets: SecurityRule = {
  ...ruleBase({
    id: 'CS-NODE-013',
    category: 'configuration_secrets',
    title: 'Exposed environment or configuration secret',
    description: 'An environment or configuration file appears to contain a real credential-like value.',
    severity: 'high',
    confidence: 'medium',
    evidenceRequirements: 'Secret-like key in an env/config file assigned to a non-placeholder literal value.',
    remediation: 'Remove committed secrets, rotate exposed credentials, and provide only placeholder values in example files.',
    falsePositiveGuidance: 'Example files with placeholders or generated local-only credentials can be marked false positive after review.',
    languages: ['node'],
  }),
  async run(context) {
    const files = [...context.profile.envFiles, ...context.profile.configFiles].filter((path) => !isDocumentationFile(path));
    const findings: SecurityFinding[] = [];
    for (const filePath of files) {
      if (isIgnoredPath(filePath)) continue;
      const file = await context.readFile(filePath);
      if (!file) continue;
      const lines = file.content.split('\n');
      for (let index = 0; index < lines.length; index++) {
        const line = lines[index];
        if (!codeLineIsExecutable(line)) continue;
        const match = /(?:^|[\s"'{])([A-Z0-9_-]*(?:api[_-]?key|secret|password|passwd|pwd|token|private[_-]?key|client[_-]?secret|access[_-]?key)[A-Z0-9_-]*)\s*[:=]\s*['"]?([^'"#\s]{8,})/i.exec(line);
        if (!match || looksLikePlaceholder(match[2])) continue;
        findings.push(makeFinding(this, {
          file: filePath,
          line: index + 1,
          matchedText: line.trim().slice(0, 240),
          context: contextFor(file.content, index + 1),
          reason: this.evidenceRequirements,
        }));
      }
    }
    return findings;
  },
};

const dangerousDependencies: SecurityRule = {
  ...ruleBase({
    id: 'CS-NODE-014',
    category: 'dependency_risk',
    title: 'Obviously dangerous dependency usage',
    description: 'Project metadata includes a dependency known to expose dangerous primitives that frequently create vulnerabilities.',
    severity: 'medium',
    confidence: 'high',
    evidenceRequirements: 'Dangerous package name found in project dependency metadata.',
    remediation: 'Remove the dependency when possible, replace it with a safer maintained alternative, or isolate and strictly validate any inputs reaching it.',
    falsePositiveGuidance: 'A package can be acceptable if it is unused, development-only, or wrapped behind strict controls; verify actual usage before prioritizing remediation.',
    languages: ['node'],
  }),
  async run(context) {
    const dangerous = new Set(['node-serialize', 'serialize-to-js', 'static-eval', 'safe-eval', 'vm2']);
    return context.profile.dependencies
      .filter((dependency: DependencyInfo) => dangerous.has(dependency.name))
      .map((dependency) =>
        makeFinding(this, {
          file: 'package.json',
          matchedText: `${dependency.name}@${dependency.version}`,
          reason: `${this.evidenceRequirements}: ${dependency.name} is listed as a ${dependency.dev ? 'devDependency' : 'dependency'}.`,
        })
      );
  },
};

const jwtVerification = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-016',
    category: 'authentication',
    title: 'JWT decoded without signature verification',
    description: 'A request-derived token is decoded without a cryptographic verification step.',
    severity: 'high',
    confidence: 'medium',
    evidenceRequirements: 'jwt.decode or equivalent is reached with request-derived token data and no visible verify call.',
    remediation: 'Verify the signature, algorithm, issuer, audience, and expiry before trusting JWT claims.',
    falsePositiveGuidance: 'The finding is not proof that a token is accepted; runtime proof requires the explicit invalid-token oracle.',
    languages: ['node'],
  }),
  String.raw`\b(jwt\.)?decode\s*\(`,
  (line) => hasTaintedInput(line) && !/\.verify\s*\(/.test(line)
);

const sessionCookieFlags = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-017',
    category: 'security_configuration',
    title: 'Session cookie missing security flags',
    description: 'A session cookie is configured with an explicitly unsafe flag value.',
    severity: 'high',
    confidence: 'high',
    evidenceRequirements: 'Cookie configuration explicitly disables secure, httpOnly, or an equivalent same-site protection.',
    remediation: 'Set Secure, HttpOnly, and an appropriate SameSite policy on session cookies.',
    falsePositiveGuidance: 'Development-only cookies may be intentionally different, but production behavior requires runtime confirmation.',
    languages: ['node'],
  }),
  String.raw`(cookie\s*\(|setHeader\s*\(|secure\s*:|httpOnly\s*:|sameSite\s*:)`,
  (line) => /(secure|httpOnly|sameSite)\s*:\s*(false|['"`]?(none|lax|strict)['"`]?)|set-cookie/i.test(line) && /(secure\s*:\s*false|httpOnly\s*:\s*false|sameSite\s*:\s*['"`]?none)/i.test(line)
);

const csrf = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-018', category: 'csrf', title: 'State-changing route lacks CSRF protection',
    description: 'A state-changing route consumes request data without a visible CSRF token or middleware.', severity: 'high', confidence: 'low',
    evidenceRequirements: 'POST/PUT/PATCH route uses request data and has no visible CSRF token or protection middleware.',
    remediation: 'Require a server-validated CSRF token or equivalent same-site request integrity control.',
    falsePositiveGuidance: 'Token validation in global middleware or a signed API-only authentication scheme may not be visible to this heuristic.', languages: ['node'],
  }),
  String.raw`\b(?:app|router)\.(post|put|patch)\s*\(`,
  (line) => /req\.(body|query|params)/.test(line) && !/(webhook|upload|profile|xsrf|sameSite|origin|referer)/i.test(line),
);

const webhookSignature = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-019', category: 'webhook_signature', title: 'Webhook handler lacks signature validation',
    description: 'A webhook-shaped route consumes a request body without a visible signature check.', severity: 'high', confidence: 'medium',
    evidenceRequirements: 'Webhook route reads request body without a visible signature header or verification call.',
    remediation: 'Verify the provider signature over the raw body before processing the event.',
    falsePositiveGuidance: 'Verification performed by upstream middleware or a framework adapter may not appear on the route line.', languages: ['node'],
  }),
  String.raw`\b(?:app|router)\.post\s*\(`,
  (line) => /webhook/i.test(line) && /req\.body/.test(line) && !/(signature|hmac|x-signature|webhooksecret)/i.test(line),
);

const massAssignment = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-020', category: 'mass_assignment', title: 'Mass assignment from request object',
    description: 'A model mutation appears to accept the request body wholesale, including fields that may control privilege.', severity: 'high', confidence: 'medium',
    evidenceRequirements: 'Create/update/assign sink receives req.body without an explicit field allowlist.',
    remediation: 'Copy only explicitly permitted fields and reject role/ownership fields from untrusted input.',
    falsePositiveGuidance: 'A schema or DTO allowlist outside the matched line may make this heuristic a false positive.', languages: ['node'],
  }),
  String.raw`(Object\.assign|\.create\s*\(|\.update\s*\(|\.save\s*\()`,
  (line) => /req\.body/.test(line) && /(Object\.assign|\.create\s*\(|\.update\s*\(|\.save\s*\()/i.test(line),
);

const weakPasswordStorage = makeSearchRule(
  ruleBase({
    id: 'CS-NODE-021', category: 'weak_password_storage', title: 'Weak password storage indicator',
    description: 'A password appears to be stored or transformed with plaintext, reversible, or obsolete hashing behavior.', severity: 'critical', confidence: 'low',
    evidenceRequirements: 'Password value is assigned directly or passed to a weak digest primitive.',
    remediation: 'Use a memory-hard password hashing scheme such as Argon2id or a carefully configured bcrypt implementation.',
    falsePositiveGuidance: 'Static matching cannot establish database persistence or effective work factor; runtime proof is intentionally unsupported.', languages: ['node'],
  }),
  String.raw`(password\s*[:=]|md5\s*\(|sha1\s*\(|createHash\s*\(['"]md5)`,
  (line) => /password\s*[:=]\s*(?:req\.|['"`])|\b(?:md5|sha1)\s*\(/i.test(line),
);

export const nodeSecurityRules: SecurityRule[] = [
  hardcodedSecrets,
  sqlNoSqlInjection,
  commandInjection,
  pathTraversal,
  ssrf,
  xss,
  openRedirect,
  insecureCors,
  weakAuthentication,
  brokenAuthorization,
  unsafeUploads,
  dangerousDeserialization,
  insecureConfiguration,
  exposedConfigSecrets,
  dangerousDependencies,
  jwtVerification,
  sessionCookieFlags,
  csrf,
  webhookSignature,
  massAssignment,
  weakPasswordStorage,
];
