import type { EntryPoint, Evidence } from '../types.js';
import { fileExists } from '../manifestReader.js';
import type { NodeAnalysisContext } from './context.js';

/**
 * Entry-point detection combines several signals: package.json's "main"
 * field, the target of the "start" script, and a short list of common
 * conventional filenames. Each candidate is deduplicated by path, and
 * evidence accumulates per-candidate rather than stopping at the first
 * match, so a file confirmed by two signals is more trustworthy than one
 * confirmed by a single guess.
 */

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
  // Matches the first bare-ish file argument to node/ts-node/nodemon, e.g.
  // "node dist/index.js", "ts-node src/index.ts", "nodemon src/server.ts".
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
    // Only report a candidate as an entry point if it actually exists on
    // disk, OR it was named by main/start (still useful even if the built
    // output doesn't exist yet, e.g. "dist/index.js" pre-build) — but we
    // downgrade confidence in that case.
    const exists = fileExists(root, path);
    const namedBySignal = evidence.some((e) => e.source !== `file:${path}`);
    if (!exists && !namedBySignal) continue;

    let confidence: 'high' | 'medium' | 'low';
    if (exists && evidence.length >= 2) confidence = 'high';
    else if (exists) confidence = 'medium';
    else confidence = 'low'; // named by main/start but file not found (e.g. unbuilt dist/)

    results.push({ path, confidence, evidence });
  }

  // Stable ordering: high confidence first, then by path for determinism.
  results.sort((a, b) => {
    const rank = { high: 0, medium: 1, low: 2 };
    if (rank[a.confidence] !== rank[b.confidence]) return rank[a.confidence] - rank[b.confidence];
    return a.path.localeCompare(b.path);
  });

  return results;
}
