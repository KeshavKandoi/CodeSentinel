export type EnvironmentBlockerKind = 'npm_cache_permissions' | 'filesystem_permissions' | 'missing_executable' | 'missing_dependency' | 'missing_runtime' | 'missing_variable' | 'port_in_use' | 'database_unavailable' | 'docker_unavailable' | 'module_resolution' | 'invalid_configuration' | 'unknown';

export interface EnvironmentBlocker {
  kind: EnvironmentBlockerKind;
  responsibility: 'user_environment' | 'target_configuration' | 'codesentinel' | 'unknown';
  reason: string;
  recommendedNextStep: string;
}

export function classifyRuntimeSetupFailure(command: string, output: string): EnvironmentBlocker {
  const text = `${command}\n${output}`.slice(0, 8_000);
  const npm = /\bnpm\b|_cacache|\.npm[/\\]/i.test(text);
  const cache = /_cacache|\.npm[/\\]/i.test(text);
  if (/(?:EPERM|EACCES|permission denied|root-owned)/i.test(text)) {
    if (npm && cache) return { kind: 'npm_cache_permissions', responsibility: 'user_environment', reason: 'Runtime verification could not start because npm encountered a filesystem permission error in the user npm cache.', recommendedNextStep: 'Repair npm cache ownership or permissions, run npm cache verify, then rerun the audit. CodeSentinel will not run sudo or change the cache.' };
    return { kind: 'filesystem_permissions', responsibility: 'user_environment', reason: 'Runtime verification could not start because a filesystem permission check failed.', recommendedNextStep: 'Inspect the reported file permissions outside CodeSentinel, repair them manually, then rerun verification.' };
  }
  if (/EADDRINUSE|address already in use|port already (?:in use|occupied)/i.test(text)) return { kind: 'port_in_use', responsibility: 'user_environment', reason: 'Runtime verification could not start because the requested port is already in use.', recommendedNextStep: 'Stop the conflicting process or select a free local port, then rerun verification.' };
  if (/ECONNREFUSED.*(?:27017|mongo)|Mongo(?:DB)?.*(?:unavailable|connect|refused)/i.test(text)) return { kind: 'database_unavailable', responsibility: 'user_environment', reason: 'Runtime verification could not start because MongoDB was unavailable.', recommendedNextStep: 'Start the required isolated MongoDB service or correct its local connection settings, then rerun verification.' };
  if (/docker.*(?:not found|unavailable|daemon.*(?:not running|connect))/i.test(text)) return { kind: 'docker_unavailable', responsibility: 'user_environment', reason: 'Runtime verification could not start because Docker was unavailable.', recommendedNextStep: 'Start Docker or provide the required local service manually, then rerun verification.' };
  if (/MODULE_NOT_FOUND|ERR_MODULE_NOT_FOUND|Cannot find module/i.test(text)) return { kind: 'module_resolution', responsibility: 'target_configuration', reason: 'Runtime verification could not start because the application could not resolve a module.', recommendedNextStep: 'Check the project dependency installation and import paths, then rerun verification.' };
  if (/command not found|ENOENT|not recognized as an internal or external command/i.test(text)) return { kind: 'missing_executable', responsibility: 'user_environment', reason: 'Runtime verification could not start because a required executable was missing.', recommendedNextStep: 'Install or configure the required runtime executable manually, then rerun verification.' };
  if (/missing (?:dependency|package)|dependency.*not installed/i.test(text)) return { kind: 'missing_dependency', responsibility: 'target_configuration', reason: 'Runtime verification could not start because a project dependency was missing.', recommendedNextStep: 'Install the project dependencies in an appropriate isolated environment, then rerun verification.' };
  if (/missing (?:environment variable|env var)|(?:environment variable|env var).*required/i.test(text)) return { kind: 'missing_variable', responsibility: 'target_configuration', reason: 'Runtime verification could not start because a required environment variable was missing.', recommendedNextStep: 'Provide the required variable through the approved runtime environment, then rerun verification.' };
  if (/database.*(?:unavailable|connect|refused)|ECONNREFUSED/i.test(text)) return { kind: 'database_unavailable', responsibility: 'user_environment', reason: 'Runtime verification could not start because a required database or service was unavailable.', recommendedNextStep: 'Start the required isolated service or correct its local connection settings, then rerun verification.' };
  if (/invalid (?:project )?config|configuration.*invalid/i.test(text)) return { kind: 'invalid_configuration', responsibility: 'target_configuration', reason: 'Runtime verification could not start because the project configuration was invalid.', recommendedNextStep: 'Correct the project runtime configuration, then rerun verification.' };
  if (/runtime.*(?:not found|missing|unavailable)/i.test(text)) return { kind: 'missing_runtime', responsibility: 'user_environment', reason: 'Runtime verification could not start because the required runtime was unavailable.', recommendedNextStep: 'Install or configure the required runtime manually, then rerun verification.' };
  return { kind: 'unknown', responsibility: 'unknown', reason: 'Runtime verification could not start because setup failed; CodeSentinel cannot safely classify the supplied error.', recommendedNextStep: 'Inspect the local setup error, correct the environment, then rerun verification.' };
}
