import { createHash } from 'node:crypto';
import type { SecurityEvidence, SecurityFinding, SecurityRule } from './types.js';

const SOURCE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);
const DOC_EXTENSIONS = new Set(['.md', '.mdx', '.txt', '.rst']);
const GENERATED_SEGMENTS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage']);

export function extensionOf(filePath: string): string {
  const match = /(\.[^./]+)$/.exec(filePath);
  return match ? match[1].toLowerCase() : '';
}

export function isSourceFile(filePath: string): boolean {
  return SOURCE_EXTENSIONS.has(extensionOf(filePath));
}

export function isDocumentationFile(filePath: string): boolean {
  return DOC_EXTENSIONS.has(extensionOf(filePath));
}

export function isIgnoredPath(filePath: string): boolean {
  return filePath.split('/').some((segment) => GENERATED_SEGMENTS.has(segment));
}

export function isCommentLine(line: string): boolean {
  const trimmed = line.trim();
  return (
    trimmed.startsWith('//') ||
    trimmed.startsWith('*') ||
    trimmed.startsWith('/*') ||
    trimmed.startsWith('#') ||
    trimmed.startsWith('<!--')
  );
}

export function hasTaintedInput(line: string): boolean {
  return /\b(req|request)\s*\.\s*(body|query|params|headers|cookies|url|originalUrl|path)\b|\bctx\s*\.\s*(request|query|params|headers|body)\b|\bevent\s*\.\s*(queryStringParameters|pathParameters|headers|body)\b/.test(line);
}

export function hasDynamicExpression(line: string): boolean {
  return /`[^`]*\$\{[^}]+}/.test(line) || /['"][^'"]*['"]\s*\+|\+\s*['"][^'"]*['"]|\+\s*[A-Za-z_$][\w$.[\]]*/.test(line);
}

export function contextFor(content: string, lineNumber: number, radius = 1): string {
  const lines = content.split('\n');
  const start = Math.max(0, lineNumber - radius - 1);
  const end = Math.min(lines.length, lineNumber + radius);
  return lines.slice(start, end).map((line, index) => `${start + index + 1}: ${line}`).join('\n');
}

export function lineAt(content: string, lineNumber: number): string {
  return content.split('\n')[lineNumber - 1] ?? '';
}

export function makeFinding(rule: SecurityRule, evidence: SecurityEvidence): SecurityFinding {
  const basis = `${rule.id}:${evidence.file ?? 'project'}:${evidence.line ?? 0}:${evidence.matchedText ?? evidence.reason}`;
  const suffix = createHash('sha256').update(basis).digest('hex').slice(0, 12);
  return {
    id: `${rule.id}-${suffix}`,
    ruleId: rule.id,
    title: rule.title,
    category: rule.category,
    severity: rule.severity,
    confidence: rule.confidence,
    status: 'suspected',
    file: evidence.file,
    line: evidence.line,
    evidence: [evidence],
    description: rule.description,
    remediation: rule.remediation,
    verificationStatus: 'not_verified',
  };
}

export function dedupeFindings(findings: SecurityFinding[]): SecurityFinding[] {
  const seen = new Set<string>();
  const unique: SecurityFinding[] = [];
  for (const finding of findings) {
    const key = `${finding.ruleId}:${finding.file ?? ''}:${finding.line ?? ''}:${finding.evidence.map((e) => e.matchedText ?? e.reason).join('|')}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(finding);
  }
  return unique.sort((a, b) => {
    const fileCompare = (a.file ?? '').localeCompare(b.file ?? '');
    if (fileCompare !== 0) return fileCompare;
    return (a.line ?? 0) - (b.line ?? 0) || a.ruleId.localeCompare(b.ruleId);
  });
}

export function codeLineIsExecutable(line: string): boolean {
  return !isCommentLine(line) && line.trim().length > 0;
}

export function looksLikePlaceholder(value: string): boolean {
  return /^(changeme|change_me|example|sample|test|secret|password|placeholder|your[_-]?(key|token|secret)|xxx+|todo|fixme)$/i.test(value.trim());
}
