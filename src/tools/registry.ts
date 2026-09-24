import { z } from 'zod';
import { logger } from '../logger.js';
import type { AppConfig } from '../config.js';
import {
  listFilesSchema,
  readFileSchema,
  searchFilesSchema,
  getProjectInfoSchema,
  runCommandSchema,
  scanProjectSchema,
  verifyFindingSchema,
  listVerificationCasesSchema,
  startSecurityInvestigationSchema,
  getInvestigationSchema,
  runSecurityAnalysisSchema,
  recordSecurityHypothesisSchema,
  runtimeVerificationRequestSchema,
  securityAgentInstructionsSchema,
  generateSecurityReportSchema,
  getSecurityFindingSchema,
  proposeRemediationSchema,
  remediationIdSchema,
  verifyRemediationSchema,
  rollbackRemediationSchema,
  safeValidate,
} from '../validation/schemas.js';
import { listFiles, readFile, searchFiles } from '../fs/fsOperations.js';
import { getProjectInfo } from './projectInfo.js';
import { runCommand, ALLOWED_COMMANDS } from '../exec/commandExecutor.js';
import type { ToolOutcome } from '../types.js';
import { ok, err } from '../types.js';
import { analyzeProjectSchema } from '../validation/schemas.js';
import { runProjectDiscovery } from '../discovery/projectDiscovery.js';
import { scanProject } from '../security/scanner.js';
import { discoverRoutesSchema } from '../validation/schemas.js';
import { discoverRoutes } from '../routes/engine.js';
import { analyzeAccessControlSchema } from '../validation/schemas.js';
import { analyzeAccessControl } from '../access/engine.js';
import { listVerificationCases, verifyFinding } from '../runtime/engine.js';
import {
  SECURITY_AGENT_INSTRUCTIONS,
  getInvestigation,
  recordHypothesis,
  requestRuntimeVerification,
  runSecurityAnalysis,
  startInvestigation,
} from '../investigation/orchestrator.js';
import { generateSecurityReport, getSecurityFinding } from '../report/engine.js';
import { applyRemediation, proposeRemediation, rollbackRemediation, verifyRemediation } from '../remediation/engine.js';


export interface McpToolResponse {
  content: Array<{ type: 'text'; text: string }>;
  isError: boolean;
}

function toMcpResponse<T>(outcome: ToolOutcome<T>): McpToolResponse {
  if (outcome.ok) {
    return {
      content: [{ type: 'text', text: JSON.stringify(outcome.data, null, 2) }],
      isError: false,
    };
  }
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify({ error: outcome.error.code, message: outcome.error.message }, null, 2),
      },
    ],
    isError: true,
  };
}

function invalidInputResponse(message: string): McpToolResponse {
  return {
    content: [{ type: 'text', text: JSON.stringify({ error: 'INVALID_INPUT', message }, null, 2) }],
    isError: true,
  };
}

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>; // JSON Schema for MCP tool listing
  handler: (config: AppConfig, rawInput: unknown) => Promise<McpToolResponse>;
}

export const toolDefinitions: ToolDefinition[] = [
  {
    name: 'list_files',
    description:
      'List files and directories within the project root. Supports recursive listing and result capping. Paths are always relative to the configured project root.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Directory path relative to project root. Defaults to "."' },
        recursive: { type: 'boolean', description: 'Recurse into subdirectories. Defaults to false.' },
        maxResults: { type: 'number', description: 'Maximum number of entries to return. Defaults to 1000.' },
      },
    },
    handler: async (config, rawInput) => {
      const validation = safeValidate(listFilesSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      logger.info('tool_execution', { tool: 'list_files', input: validation.data });
      const result = listFiles(config, {
        dirPath: validation.data.path,
        recursive: validation.data.recursive,
        maxResults: validation.data.maxResults,
      });
      return toMcpResponse(result);
    },
  },
  {
    name: 'read_file',
    description:
      'Read the contents of a single file within the project root. Returns UTF-8 text; large files are truncated to a configured byte limit.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'File path relative to project root.' },
        maxBytes: { type: 'number', description: 'Optional override for max bytes to read.' },
      },
      required: ['path'],
    },
    handler: async (config, rawInput) => {
      const validation = safeValidate(readFileSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      logger.info('tool_execution', { tool: 'read_file', input: validation.data });
      const result = readFile(config, {
        filePath: validation.data.path,
        maxBytes: validation.data.maxBytes,
      });
      return toMcpResponse(result);
    },
  },
  {
    name: 'search_files',
    description:
      'Search file contents for a text or regex pattern within the project root, returning matching lines with file path and line number.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Text or regex pattern to search for.' },
        path: { type: 'string', description: 'Directory to search within. Defaults to "."' },
        caseSensitive: { type: 'boolean', description: 'Case-sensitive match. Defaults to false.' },
        isRegex: { type: 'boolean', description: 'Treat query as a regular expression. Defaults to false.' },
        maxResults: { type: 'number', description: 'Maximum number of matches to return. Defaults to 500.' },
      },
      required: ['query'],
    },
    handler: async (config, rawInput) => {
      const validation = safeValidate(searchFilesSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      logger.info('tool_execution', { tool: 'search_files', input: validation.data });
      const result = searchFiles(config, {
        query: validation.data.query,
        dirPath: validation.data.path,
        caseSensitive: validation.data.caseSensitive,
        isRegex: validation.data.isRegex,
        maxResults: validation.data.maxResults,
      });
      return toMcpResponse(result);
    },
  },
  {
    name: 'get_project_info',
    description:
      'Return metadata about the configured project: detected language/framework markers, package manager, git status, and file/directory counts.',
    inputSchema: { type: 'object', properties: {} },
    handler: async (config, rawInput) => {
      const validation = safeValidate(getProjectInfoSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      logger.info('tool_execution', { tool: 'get_project_info' });
      const result = getProjectInfo(config);
      return toMcpResponse(result);
    },
  },
  {
    name: 'analyze_project',
    description:
      'Analyze the project to detect its programming language(s), package manager, frontend/backend frameworks, database, ORM, test framework, entry points, build/start/test scripts, Docker configuration, environment/config files, and authentication-related dependencies. Returns a normalized ProjectProfile with evidence for every detected item. Read-only; does not perform vulnerability or security analysis.',
    inputSchema: { type: 'object', properties: {} },
    handler: async (config, rawInput) => {
      const validation = safeValidate(analyzeProjectSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      logger.info('tool_execution', { tool: 'analyze_project' });
      try {
        const profile = runProjectDiscovery(config.projectRoot);
        return toMcpResponse(ok(profile));
      } catch (e) {
        logger.error('analyze_project_failed', { message: (e as Error).message });
        return toMcpResponse(err('INTERNAL_ERROR', 'Project analysis failed unexpectedly.'));
      }
    },
  },
  {
    name: 'scan_project',
    description:
      'Run deterministic Phase 3 static security analysis against the authorized project. Returns normalized SecurityFinding objects with rule IDs, severity, confidence, status, source evidence, remediation, and verification status. Read-only; does not exploit, modify, or retest code.',
    inputSchema: { type: 'object', properties: {} },
    handler: async (config, rawInput) => {
      const validation = safeValidate(scanProjectSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      logger.info('tool_execution', { tool: 'scan_project' });
      try {
        const result = await scanProject(config);
        return toMcpResponse(result);
      } catch (e) {
        logger.error('scan_project_failed', { message: (e as Error).message });
        return toMcpResponse(err('INTERNAL_ERROR', 'Security scan failed unexpectedly.'));
      }
    },
  },
  {
    name: 'discover_routes',
    description:
      'Run Phase 4 static attack-surface discovery. Uses the Phase 2 ProjectProfile to pick framework adapters and returns a normalized inventory of externally reachable routes (method, path, source location, handler, middleware/dependencies, parameters, auth/authorization/upload indicators, public-or-protected, confidence, and evidence), plus a framework summary, counts, and warnings. Read-only and static: never starts the application or sends HTTP requests.',
    inputSchema: { type: 'object', properties: {} },
    handler: async (config, rawInput) => {
      const validation = safeValidate(discoverRoutesSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      logger.info('tool_execution', { tool: 'discover_routes' });
      try {
        return toMcpResponse(discoverRoutes(config));
      } catch (e) {
        logger.error('discover_routes_failed', { message: (e as Error).message });
        return toMcpResponse(err('INTERNAL_ERROR', 'Route discovery failed unexpectedly.'));
      }
    },
  },
  {
    name: 'analyze_access_control',
    description:
      "Run Phase 5 static access-control analysis. Uses the Phase 4 attack-surface inventory (discover_routes) and the Phase 1-2 sandboxed source access to classify each route's authentication/authorization state (public, authenticated, role_protected, permission_protected, ownership_protected, mixed, unknown) and produce suspected findings for missing authentication, missing authorization, IDOR/BOLA candidates, and inconsistent authorization across methods on the same resource -- each with confidence and evidence. Read-only and static: never starts the application, sends HTTP requests, or executes project code.",
    inputSchema: { type: 'object', properties: {} },
    handler: async (config, rawInput) => {
      const validation = safeValidate(analyzeAccessControlSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      logger.info('tool_execution', { tool: 'analyze_access_control' });
      try {
        const routesOutcome = discoverRoutes(config);
        if (!routesOutcome.ok) return toMcpResponse(routesOutcome);
        const result = analyzeAccessControl(config, routesOutcome.data.entries);
        return toMcpResponse(ok(result));
      } catch (e) {
        logger.error('analyze_access_control_failed', { message: (e as Error).message });
        return toMcpResponse(err('INTERNAL_ERROR', 'Access-control analysis failed unexpectedly.'));
      }
    },
  },
  {
    name: 'list_verification_cases',
    description:
      'List deterministic Phase 6 verification cases derived from the current Phase 5 access-control findings. This is discovery-only and never sends requests; findings are recomputed from the current project because no finding database is persisted.',
    inputSchema: { type: 'object', properties: {} },
    handler: async (config, rawInput) => {
      const validation = safeValidate(listVerificationCasesSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      try {
        return toMcpResponse(ok(listVerificationCases(config)));
      } catch (e) {
        logger.error('list_verification_cases_failed', { message: (e as Error).message });
        return toMcpResponse(err('INTERNAL_ERROR', 'Verification-case discovery failed unexpectedly.'));
      }
    },
  },
  {
    name: 'verify_finding',
    description:
      'Run one narrowly scoped Phase 6 runtime verification case for an explicit current Phase 5 finding and explicitly authorized target. Requests are bounded, evidence is redacted, and static finding status remains suspected while runtime verification is attached separately.',
    inputSchema: {
      type: 'object',
      properties: {
        findingId: { type: 'string' },
        target: { type: 'object' },
        sessions: { type: 'array' },
        sessionParams: { type: 'object' },
      },
      required: ['findingId', 'target'],
    },
    handler: async (config, rawInput) => {
      const validation = safeValidate(verifyFindingSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      try {
        const result = await verifyFinding(config, validation.data);
        if (!result.ok) return toMcpResponse(err(result.error.code, result.error.message));
        return toMcpResponse(ok(result.data));
      } catch (e) {
        logger.error('verify_finding_failed', { message: (e as Error).message });
        return toMcpResponse(err('INTERNAL_ERROR', 'Runtime verification failed unexpectedly.'));
      }
    },
  },
  {
    name: 'start_security_investigation',
    description:
      'Create a bounded Phase 7 security investigation for the configured project. The external AI agent supplies the reasoning; CodeSentinel enforces the project boundary, analysis budget, evidence cap, and later state transitions.',
    inputSchema: {
      type: 'object',
      properties: { projectPath: { type: 'string' }, scope: { type: 'array' }, hypothesis: { type: 'string' }, budget: { type: 'object' } },
      required: ['projectPath', 'scope', 'hypothesis'],
    },
    handler: async (config, rawInput) => {
      const validation = safeValidate(startSecurityInvestigationSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      return toMcpResponse(startInvestigation(config, validation.data));
    },
  },
  {
    name: 'get_investigation',
    description: 'Return bounded, redacted state and evidence for one Phase 7 security investigation.',
    inputSchema: { type: 'object', properties: { investigationId: { type: 'string' } }, required: ['investigationId'] },
    handler: async (_config, rawInput) => {
      const validation = safeValidate(getInvestigationSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      return toMcpResponse(getInvestigation(validation.data.investigationId));
    },
  },
  {
    name: 'run_security_analysis',
    description: 'Run the existing deterministic discovery, scanner, route, and access-control pipeline for an investigation exactly once.',
    inputSchema: { type: 'object', properties: { investigationId: { type: 'string' } }, required: ['investigationId'] },
    handler: async (config, rawInput) => {
      const validation = safeValidate(runSecurityAnalysisSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      return toMcpResponse(await runSecurityAnalysis(config, validation.data.investigationId));
    },
  },
  {
    name: 'record_security_hypothesis',
    description: 'Record one evidence-backed security hypothesis. Evidence references must come from the investigation analysis; no unsupported hypothesis is accepted.',
    inputSchema: { type: 'object', properties: { investigationId: { type: 'string' }, title: { type: 'string' }, description: { type: 'string' }, findingId: { type: 'string' }, evidenceRefs: { type: 'array' }, severity: { type: 'string' }, confidence: { type: 'string' } }, required: ['investigationId', 'title', 'description', 'evidenceRefs'] },
    handler: async (config, rawInput) => {
      const validation = safeValidate(recordSecurityHypothesisSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      return toMcpResponse(await recordHypothesis(config, validation.data));
    },
  },
  {
    name: 'request_runtime_verification',
    description: 'Delegate one evidence-backed hypothesis to the existing Phase 6 verify_finding implementation. It cannot issue arbitrary HTTP requests or bypass Phase 6 target/session safety controls.',
    inputSchema: { type: 'object', properties: { investigationId: { type: 'string' }, hypothesisId: { type: 'string' }, findingId: { type: 'string' }, target: { type: 'object' }, sessions: { type: 'array' }, sessionParams: { type: 'object' } }, required: ['investigationId', 'hypothesisId', 'findingId', 'target'] },
    handler: async (config, rawInput) => {
      const validation = safeValidate(runtimeVerificationRequestSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      return toMcpResponse(await requestRuntimeVerification(config, validation.data));
    },
  },
  {
    name: 'get_security_agent_instructions',
    description: 'Return the bounded workflow instructions for an external MCP-compatible security agent. No model or provider API is called by CodeSentinel.',
    inputSchema: { type: 'object', properties: {} },
    handler: async (_config, rawInput) => {
      const validation = safeValidate(securityAgentInstructionsSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      return toMcpResponse(ok({ instructions: SECURITY_AGENT_INSTRUCTIONS }));
    },
  },
  {
    name: 'generate_security_report',
    description: 'Generate a bounded, deterministic, evidence-traceable Phase 8 security report and remediation plan for a completed investigation. It never modifies source code or calls an LLM.',
    inputSchema: { type: 'object', properties: { investigationId: { type: 'string' } }, required: ['investigationId'] },
    handler: async (_config, rawInput) => {
      const validation = safeValidate(generateSecurityReportSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      try {
        return toMcpResponse(generateSecurityReport(validation.data.investigationId));
      } catch (e) {
        logger.error('generate_security_report_failed', { message: (e as Error).message });
        return toMcpResponse(err('INTERNAL_ERROR', 'Security report generation failed unexpectedly.'));
      }
    },
  },
  {
    name: 'get_security_finding',
    description: 'Return one bounded finding-focused view from an investigation, including traceable evidence and deterministic remediation guidance.',
    inputSchema: { type: 'object', properties: { investigationId: { type: 'string' }, findingId: { type: 'string' } }, required: ['investigationId', 'findingId'] },
    handler: async (_config, rawInput) => {
      const validation = safeValidate(getSecurityFindingSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      try {
        return toMcpResponse(getSecurityFinding(validation.data.investigationId, validation.data.findingId));
      } catch (e) {
        logger.error('get_security_finding_failed', { message: (e as Error).message });
        return toMcpResponse(err('INTERNAL_ERROR', 'Security finding retrieval failed unexpectedly.'));
      }
    },
  },
  {
    name: 'propose_remediation',
    description: 'Validate and store an external AI remediation proposal. It never modifies files, executes commands, or calls an AI provider.',
    inputSchema: { type: 'object', properties: { investigationId: { type: 'string' }, findingId: { type: 'string' }, description: { type: 'string' }, rationale: { type: 'string' }, files: { type: 'array' }, expectedSecurityEffect: { type: 'string' }, requiresRuntimeVerification: { type: 'boolean' }, runtimeVerification: { type: 'object' } }, required: ['investigationId', 'findingId', 'description', 'rationale', 'files', 'expectedSecurityEffect', 'requiresRuntimeVerification'] },
    handler: async (config, rawInput) => {
      const validation = safeValidate(proposeRemediationSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      return toMcpResponse(await proposeRemediation(config, validation.data));
    },
  },
  {
    name: 'apply_remediation',
    description: 'Apply one validated, hash-checked remediation proposal using bounded filesystem writes. The result remains pending verification.',
    inputSchema: { type: 'object', properties: { remediationId: { type: 'string' } }, required: ['remediationId'] },
    handler: async (config, rawInput) => {
      const validation = safeValidate(remediationIdSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      return toMcpResponse(await applyRemediation(config, validation.data.remediationId));
    },
  },
  {
    name: 'verify_remediation',
    description: 'Rerun deterministic analysis and authorized runtime verification for an applied remediation, then classify the result and regressions.',
    inputSchema: { type: 'object', properties: { remediationId: { type: 'string' } }, required: ['remediationId'] },
    handler: async (config, rawInput) => {
      const validation = safeValidate(verifyRemediationSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      return toMcpResponse(await verifyRemediation(config, validation.data.remediationId));
    },
  },
  {
    name: 'rollback_remediation',
    description: 'Restore a remediation snapshot only when every file still has its expected post-remediation hash.',
    inputSchema: { type: 'object', properties: { remediationId: { type: 'string' } }, required: ['remediationId'] },
    handler: async (config, rawInput) => {
      const validation = safeValidate(rollbackRemediationSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      return toMcpResponse(await rollbackRemediation(config, validation.data.remediationId));
    },
  },
  {
    name: 'run_command',
    description: `Execute an allowlisted, read-only command inside the project root with a timeout. Allowed commands: ${[...ALLOWED_COMMANDS].join(', ')}. No shell interpretation is performed; mutating subcommands (e.g. git push, npm install) are blocked.`,
    inputSchema: {
      type: 'object',
      properties: {
        command: { type: 'string', description: 'Executable name, must be in the allowlist.' },
        args: { type: 'array', items: { type: 'string' }, description: 'Command arguments.' },
      },
      required: ['command'],
    },
    handler: async (config, rawInput) => {
      const validation = safeValidate(runCommandSchema, rawInput ?? {});
      if (!validation.ok) return invalidInputResponse(validation.message);
      logger.info('tool_execution', {
        tool: 'run_command',
        command: validation.data.command,
        args: validation.data.args,
      });
      const result = await runCommand(config, {
        command: validation.data.command,
        args: validation.data.args,
      });
      return toMcpResponse(result);
    },
  },
];
