import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { loadConfig, type AppConfig } from './config.js';
import { logger } from './logger.js';
import { toolDefinitions } from './tools/registry.js';

async function main(): Promise<void> {
  let config: AppConfig;
  try {
    config = loadConfig();
  } catch (e) {
    // Config errors happen before the transport is up — fine to write to
    // stderr and exit non-zero; nothing has touched stdout yet.
    logger.error('config_load_failed', { message: (e as Error).message });
    process.stderr.write(`Fatal: ${(e as Error).message}\n`);
    process.exit(1);
  }

  logger.info('server_starting', {
    projectRoot: config.projectRoot,
    commandTimeoutMs: config.commandTimeoutMs,
    toolCount: toolDefinitions.length,
  });

  const server = new Server(
    { name: 'security-auditor-mcp', version: '1.0.0' },
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

  // Return type is deliberately loosened to Promise<any> here: the
  // installed MCP SDK's CallToolResult type includes an experimental
  // "tasks" discriminated-union branch that our plain
  // { content, isError } responses don't need to participate in. The
  // actual runtime shape we return is McpToolResponse, validated by our
  // own toMcpResponse()/invalidInputResponse() helpers in registry.ts.
  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<any> => {
    const { name, arguments: args } = request.params;
    const tool = toolDefinitions.find((t) => t.name === name);

    if (!tool) {
      logger.warn('unknown_tool_requested', { tool: name });
      return {
        content: [{ type: 'text', text: JSON.stringify({ error: 'UNKNOWN_TOOL', message: `No such tool: ${name}` }) }],
        isError: true,
      };
    }

    try {
      return await tool.handler(config, args);
    } catch (e) {
      // Last-resort safety net: a handler should never throw (all internal
      // ops return ToolOutcome), but if something unexpected happens we
      // still must not crash the server or leak a raw stack trace over the
      // transport.
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
