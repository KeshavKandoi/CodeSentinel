import { toolDefinitions } from './dist/tools/registry.js';

const tool = toolDefinitions.find((t) => t.name === 'analyze_access_control');
if (!tool) {
  console.error('FAIL: analyze_access_control not found in toolDefinitions');
  process.exit(1);
}
console.log('Tool registered:', tool.name);

const config = {
  projectRoot: process.argv[2],
  commandTimeoutMs: 5000,
  maxOutputBytes: 1_000_000,
  maxReadFileBytes: 2_000_000,
  maxListResults: 2_000,
};

const res = await tool.handler(config, {});
console.log('isError:', res.isError);
const parsed = JSON.parse(res.content[0].text);
console.log('project:', parsed.project);
console.log('frameworks:', parsed.frameworks);
console.log('summary:', JSON.stringify(parsed.summary, null, 2));
console.log('sample matrix entry:', JSON.stringify(parsed.matrix?.[0], null, 2));
console.log('findings count:', parsed.findings?.length);
if (parsed.findings?.length) console.log('sample finding:', JSON.stringify(parsed.findings[0], null, 2));
console.log('warnings:', parsed.warnings);
