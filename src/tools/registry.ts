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
