import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { loadConfigAllowUnset, type AppConfig } from './config.js';
import { logger } from './logger.js';
import { redactReportValue } from './report/redaction.js';
import { toolDefinitions } from './tools/registry.js';

async function main(): Promise<void> {
  let config: AppConfig;
  try {
    config = loadConfigAllowUnset();
  } catch (e) {
    logger.error('config_load_failed', { message: (e as Error).message });
    process.stderr.write(`Fatal: ${(e as Error).message}\n`);
    process.exit(1);
  }

  if (!config.projectRoot) {
    logger.warn('project_root_unset', { message: 'PROJECT_ROOT is not set. Read-only tools require projectRoot in each call; all other tools are unavailable.' });
  }

  logger.info('server_starting', {
    projectRoot: config.projectRoot,
    commandTimeoutMs: config.commandTimeoutMs,
    toolCount: toolDefinitions.length,
  });

  const server = new Server(
    { name: 'CodeSentinel', version: '1.0.0' },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: toolDefinitions.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      })),
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<any> => {
    const { name, arguments: args } = request.params;
    const tool = toolDefinitions.find((t) => t.name === name);

    if (!tool) {
      logger.warn('unknown_tool_requested', { tool: name });
      return {
        content: [{ type: 'text', text: JSON.stringify({ error: 'UNKNOWN_TOOL', message: `No such tool: ${String(redactReportValue(String(name).slice(0, 64)))}` }) }],
        isError: true,
      };
    }

    try {
      return await tool.handler(config, args);
    } catch (e) {
      logger.error('tool_handler_uncaught_error', { tool: name, message: (e as Error).message });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ error: 'INTERNAL_ERROR', message: 'An unexpected error occurred.' }),
          },
        ],
        isError: true,
      };
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info('server_ready', { transport: 'stdio' });
}

main().catch((e) => {
  logger.error('fatal_startup_error', { message: (e as Error).message });
  process.stderr.write(`Fatal startup error: ${(e as Error).message}\n`);
  process.exit(1);
});
