import { runProjectDiscovery } from '../discovery/projectDiscovery.js';
import { listFiles, readFile, searchFiles } from '../fs/fsOperations.js';
import type { AppConfig } from '../config.js';
import { ok, type SearchMatch, type ToolOutcome } from '../types.js';
import { getSecurityRules } from './ruleRegistry.js';
import { resolveToolRoot } from '../projectRoot.js';
import type { SecurityFinding, SecurityScanContext, SecurityScanResult, SecuritySeverity } from './types.js';
import { addBoundedWarning, dedupeFindings, isSourceFile, redactSecurityText } from './utils.js';

const severities: SecuritySeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

export async function scanProject(config: AppConfig): Promise<ToolOutcome<SecurityScanResult>> {
  const checkedRoot = resolveToolRoot(config, config.projectRoot);
  if (!checkedRoot.ok) return checkedRoot;
  config = { ...config, projectRoot: checkedRoot.data };
  const warnings: string[] = [];
  const profile = runProjectDiscovery(config.projectRoot);
  for (const warning of profile.warnings) addBoundedWarning(warnings, warning);

  const fileCache = new Map<string, Awaited<ReturnType<typeof readFile>>>();
  const analyzedPaths = new Set<string>();
  const context: SecurityScanContext = {
    config,
    profile,
    async search(query, options = {}): Promise<SearchMatch[]> {
      const result = searchFiles(config, {
        query,
        dirPath: options.path ?? '.',
        caseSensitive: options.caseSensitive ?? false,
        isRegex: options.isRegex ?? true,
        maxResults: options.maxResults ?? 10_000,
        allowSensitive: true,
        onFileRead: (filePath) => { analyzedPaths.add(filePath); },
      });
      if (!result.ok) {
        addBoundedWarning(warnings, `Search failed for pattern "${query}": ${result.error.message}`);
        return [];
      }
      return result.data;
    },
    async readFile(filePath) {
      if (!fileCache.has(filePath)) {
        fileCache.set(filePath, readFile(config, { filePath, allowSensitive: true }));
      }
      const result = fileCache.get(filePath);
      if (!result?.ok) {
        if (result && !result.ok) addBoundedWarning(warnings, `Could not read ${filePath}: ${result.error.message}`);
        return null;
      }
      if (!result.data.truncated) analyzedPaths.add(filePath);
      return result.data;
    },
    warn(message) { if (!warnings.includes(message)) addBoundedWarning(warnings, message); },
    recordFile(filePath) { analyzedPaths.add(filePath); },
  };

  // Do not run a language-specific rule set against an unsupported ecosystem.
  // In particular, Python projects must remain explicitly unsupported rather
  // than receiving misleading Node regex findings.
  const allRules = getSecurityRules();
  const rules = allRules.filter((rule) => rule.languages.includes(profile.ecosystem));
  const rulesSkipped = allRules.filter((rule) => !rule.languages.includes(profile.ecosystem)).map((rule) => ({
    ruleId: rule.id,
    reason: `Rule supports ${rule.languages.join(', ')}; detected ecosystem is ${profile.ecosystem}.`,
  }));
  const rulesRun: string[] = [];
  const rulesFailed: SecurityScanResult['rulesFailed'] = [];
  const allFindings: SecurityFinding[] = [];
  for (const rule of rules) {
    try {
      allFindings.push(...await rule.run(context));
      rulesRun.push(rule.id);
    } catch (e) {
      addBoundedWarning(warnings, `Rule ${rule.id} failed: ${(e as Error).message}`);
      rulesFailed.push({ ruleId: rule.id, reason: redactSecurityText((e as Error).message).slice(0, 400) });
    }
  }

  const findings = dedupeFindings(allFindings);
  const listed = listFiles(config, { dirPath: '.', recursive: true, maxResults: config.maxListResults });
  if (!listed.ok) addBoundedWarning(warnings, `Source inventory failed: ${listed.error.message}`);
  const inventory = listed.ok ? listed.data.filter((entry) => entry.type === 'file') : [];
  const candidates = inventory.filter((entry) => isSourceFile(entry.path) || entry.path === 'package.json');
  const skippedFiles = candidates.filter((entry) => !analyzedPaths.has(entry.path)).map((entry) => ({
    file: entry.path,
    reason: entry.sizeBytes !== undefined && entry.sizeBytes > config.maxReadFileBytes ? 'File exceeds configured read limit.' : 'File was not inspected by the enabled rules.',
  }));
  const inventoryTruncated = listed.ok && listed.data.length >= config.maxListResults;
  if (inventoryTruncated) addBoundedWarning(warnings, 'Source inventory reached MAX_LIST_RESULTS; file coverage is incomplete.');
  const fileAnalysis: SecurityScanResult['fileAnalysis'] = {
    discovered: candidates.length,
    analyzed: candidates.filter((entry) => analyzedPaths.has(entry.path)).length,
    skipped: skippedFiles.length,
    unsupportedExtensions: inventory.length - candidates.length,
    inventoryTruncated,
    skippedFiles: skippedFiles.slice(0, 50),
  };
  const limitations = [
    'Static matches are suspected findings, not verified vulnerabilities; runtime verification was not performed.',
    'The file inventory is bounded and covers JavaScript/TypeScript source plus the root package.json; not every framework or source-to-sink path is modeled.',
  ];
  if (profile.ecosystem !== 'node') limitations.push(`No security rules support the detected ${profile.ecosystem} ecosystem in this scan.`);
  if (fileAnalysis.skipped > 0 || fileAnalysis.inventoryTruncated) limitations.push('Some candidate files were not fully inspected; see fileAnalysis and warnings.');
  if (rulesFailed.length > 0) limitations.push('One or more rules failed; their results are absent from this scan.');
  const message = profile.ecosystem === 'unknown'
    ? profile.nestedProjects.length > 0
      ? 'Nested Node project(s) were found. No rules ran for this root; pass projectRoot for the intended application.'
      : 'Project ecosystem could not be determined. No supported security rules ran; select a supported application root.'
    : rulesRun.length === 0
      ? `No security rules ran for the ${profile.ecosystem} ecosystem.`
      : findings.length === 0
        ? 'No vulnerabilities were detected by the enabled static-analysis rules. This does not prove the project is secure.'
        : `${findings.length} static security candidate(s) detected; runtime verification was not performed.`;
  return ok({
    project: {
      root: config.projectRoot,
      name: profile.projectName,
      ecosystem: profile.ecosystem,
      support: profile.ecosystem === 'node' ? 'supported' : profile.ecosystem === 'unknown' ? 'unknown' : 'unsupported',
      nestedProjects: profile.nestedProjects,
      packageManager: profile.packageManager?.name ?? null,
      gitStatus: 'not_checked',
    },
    summary: summarize(findings),
    rulesRun,
    rulesSkipped,
    rulesFailed,
    ruleExecution: { executed: rulesRun.length, skipped: rulesSkipped.length, failed: rulesFailed.length },
    fileAnalysis,
    message,
    limitations,
    runtimeVerificationPerformed: false,
    findings,
    warnings: [...new Set(warnings)],
  });
}

function summarize(findings: SecurityFinding[]): SecurityScanResult['summary'] {
  const bySeverity = Object.fromEntries(severities.map((severity) => [severity, 0])) as Record<SecuritySeverity, number>;
  const byCategory: SecurityScanResult['summary']['byCategory'] = {};
  const byConfidence: SecurityScanResult['summary']['byConfidence'] = { high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
    byCategory[finding.category] = (byCategory[finding.category] ?? 0) + 1;
    byConfidence[finding.confidence] += 1;
  }
  return { total: findings.length, bySeverity, byCategory, byConfidence };
}
