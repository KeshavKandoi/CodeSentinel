import type { EntryPoint, Evidence } from '../types.js';
import { fileExists } from '../manifestReader.js';
import type { NodeAnalysisContext } from './context.js';


const CONVENTIONAL_ENTRY_CANDIDATES = [
  'src/index.ts',
  'src/index.js',
  'src/main.ts',
  'src/main.js',
  'src/server.ts',
  'src/server.js',
  'src/app.ts',
  'src/app.js',
  'index.ts',
  'index.js',
  'server.ts',
  'server.js',
  'app.ts',
  'app.js',
  'pages/_app.tsx',
  'pages/_app.jsx',
  'pages/_app.ts',
  'pages/_app.js',
  'src/pages/_app.tsx',
  'src/pages/_app.js',
  'app/layout.tsx',
  'app/layout.ts',
  'app/page.tsx',
];

function extractScriptEntryPath(scriptCmd: string | undefined): string | null {
  if (!scriptCmd) return null;
  const match = scriptCmd.match(/(?:node|ts-node|nodemon|node --loader ts-node\/esm)\s+(?:--[\w-]+(?:=\S+)?\s+)*([^\s]+\.(?:js|ts|mjs|cjs))/);
  return match ? match[1] : null;
}

export function detectEntryPoints(root: string, ctx: NodeAnalysisContext): EntryPoint[] {
  const candidates = new Map<string, Evidence[]>();

  const addCandidate = (path: string, evidence: Evidence) => {
    const normalized = path.replace(/^\.\//, '');
    const existing = candidates.get(normalized);
    if (existing) {
      existing.push(evidence);
    } else {
      candidates.set(normalized, [evidence]);
    }
  };

  if (ctx.pkg?.main) {
    addCandidate(ctx.pkg.main, { source: 'package.json main', detail: `"main" field points to ${ctx.pkg.main}` });
  }

  const startScript = ctx.pkg?.scripts?.start;
  const scriptEntry = extractScriptEntryPath(startScript);
  if (scriptEntry) {
    addCandidate(scriptEntry, { source: 'package.json scripts.start', detail: `"start" script runs ${scriptEntry}` });
  }

  for (const candidate of CONVENTIONAL_ENTRY_CANDIDATES) {
    if (fileExists(root, candidate)) {
      addCandidate(candidate, { source: `file:${candidate}`, detail: `Conventional entry point file exists at ${candidate}` });
    }
  }

  const results: EntryPoint[] = [];
  for (const [path, evidence] of candidates.entries()) {
    const exists = fileExists(root, path);
    const namedBySignal = evidence.some((e) => e.source !== `file:${path}`);
    if (!exists && !namedBySignal) continue;

    let confidence: 'high' | 'medium' | 'low';
    if (exists && evidence.length >= 2) confidence = 'high';
    else if (exists) confidence = 'medium';
    else confidence = 'low';

    results.push({ path, confidence, evidence });
  }

  results.sort((a, b) => {
    const rank = { high: 0, medium: 1, low: 2 };
    if (rank[a.confidence] !== rank[b.confidence]) return rank[a.confidence] - rank[b.confidence];
    return a.path.localeCompare(b.path);
  });

  return results;
}
