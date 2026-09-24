import { runProjectDiscovery } from '../discovery/projectDiscovery.js';
import { readFile, searchFiles } from '../fs/fsOperations.js';
import type { AppConfig } from '../config.js';
import { ok, type SearchMatch, type ToolOutcome } from '../types.js';
import { getSecurityRules } from './ruleRegistry.js';
import type { SecurityFinding, SecurityScanContext, SecurityScanResult, SecuritySeverity } from './types.js';
import { dedupeFindings } from './utils.js';

const severities: SecuritySeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

export async function scanProject(config: AppConfig): Promise<ToolOutcome<SecurityScanResult>> {
  const warnings: string[] = [];
  const profile = runProjectDiscovery(config.projectRoot);
  warnings.push(...profile.warnings);

  const fileCache = new Map<string, Awaited<ReturnType<typeof readFile>>>();
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
      });
      if (!result.ok) {
        warnings.push(`Search failed for pattern "${query}": ${result.error.message}`);
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
        if (result && !result.ok) warnings.push(`Could not read ${filePath}: ${result.error.message}`);
        return null;
      }
      return result.data;
    },
  };

  // Do not run a language-specific rule set against an unsupported ecosystem.
  // In particular, Python projects must remain explicitly unsupported rather
  // than receiving misleading Node regex findings.
  const rules = getSecurityRules().filter((rule) => rule.languages.includes(profile.ecosystem));
  const allFindings: SecurityFinding[] = [];
  for (const rule of rules) {
    try {
      allFindings.push(...await rule.run(context));
    } catch (e) {
      warnings.push(`Rule ${rule.id} failed: ${(e as Error).message}`);
    }
  }

  const findings = dedupeFindings(allFindings);
  return ok({
    project: {
      name: profile.projectName,
      ecosystem: profile.ecosystem,
    },
    summary: summarize(findings),
    rulesRun: rules.map((rule) => rule.id),
    findings,
    warnings,
  });
}

function summarize(findings: SecurityFinding[]): SecurityScanResult['summary'] {
  const bySeverity = Object.fromEntries(severities.map((severity) => [severity, 0])) as Record<SecuritySeverity, number>;
  const byCategory: SecurityScanResult['summary']['byCategory'] = {};
  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
    byCategory[finding.category] = (byCategory[finding.category] ?? 0) + 1;
  }
  return { total: findings.length, bySeverity, byCategory };
}
