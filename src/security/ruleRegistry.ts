import type { SecurityRule } from './types.js';
import { nodeSecurityRules } from './rules/nodeRules.js';

const registeredRules: SecurityRule[] = [...nodeSecurityRules];

export function getSecurityRules(): SecurityRule[] {
  return [...registeredRules];
}

export function registerSecurityRule(rule: SecurityRule): void {
  if (registeredRules.some((existing) => existing.id === rule.id)) {
    throw new Error(`Duplicate security rule id: ${rule.id}`);
  }
  registeredRules.push(rule);
}
