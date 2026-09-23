import type { AppConfig } from '../config.js';
import type { ProjectProfile, Confidence } from '../discovery/types.js';
import type { ReadFileResult } from '../fs/fsOperations.js';
import type { SearchMatch } from '../types.js';

export type SecuritySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type SecurityCategory =
  | 'secrets'
  | 'injection'
  | 'command_injection'
  | 'path_traversal'
  | 'ssrf'
  | 'xss'
  | 'cors'
  | 'authentication'
  | 'authorization'
  | 'file_upload'
  | 'deserialization'
  | 'security_configuration'
  | 'configuration_secrets'
  | 'dependency_risk';
export type SecurityFindingStatus = 'suspected' | 'confirmed' | 'false_positive' | 'verified';
export type VerificationStatus = 'not_verified' | 'statically_verified' | 'manually_verified' | 'not_applicable';

export interface SecurityEvidence {
  file?: string;
  line?: number;
  column?: number;
  matchedText?: string;
  context?: string;
  reason: string;
}

export interface SecurityFinding {
  id: string;
  ruleId: string;
  title: string;
  category: SecurityCategory;
  severity: SecuritySeverity;
  confidence: Confidence;
  status: SecurityFindingStatus;
  file?: string;
  line?: number;
  evidence: SecurityEvidence[];
  description: string;
  remediation: string;
  verificationStatus: VerificationStatus;
}

export interface SecurityRuleMetadata {
  id: string;
  category: SecurityCategory;
  title: string;
  description: string;
  severity: SecuritySeverity;
  confidence: Confidence;
  evidenceRequirements: string;
  remediation: string;
  falsePositiveGuidance: string;
  languages: string[];
}

export interface SecurityRule extends SecurityRuleMetadata {
  run(context: SecurityScanContext): Promise<SecurityFinding[]>;
}

export interface SecurityScanContext {
  config: AppConfig;
  profile: ProjectProfile;
  search(query: string, options?: Partial<{ path: string; caseSensitive: boolean; isRegex: boolean; maxResults: number }>): Promise<SearchMatch[]>;
  readFile(path: string): Promise<ReadFileResult | null>;
}

export interface SecurityScanResult {
  project: {
    name: string | null;
    ecosystem: ProjectProfile['ecosystem'];
  };
  summary: {
    total: number;
    bySeverity: Record<SecuritySeverity, number>;
    byCategory: Partial<Record<SecurityCategory, number>>;
  };
  rulesRun: string[];
  findings: SecurityFinding[];
  warnings: string[];
}
