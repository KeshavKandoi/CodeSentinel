import type { DockerInfo, Evidence } from '../types.js';
import { fileExists } from '../manifestReader.js';

const DOCKERFILE_CANDIDATES = ['Dockerfile', 'dockerfile', 'Dockerfile.dev', 'Dockerfile.prod'];
const COMPOSE_CANDIDATES = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'];

export function detectDocker(root: string): DockerInfo {
  const files: string[] = [];
  const evidence: Evidence[] = [];

  for (const name of DOCKERFILE_CANDIDATES) {
    if (fileExists(root, name)) {
      files.push(name);
      evidence.push({ source: `file:${name}`, detail: `${name} is present` });
    }
  }
  for (const name of COMPOSE_CANDIDATES) {
    if (fileExists(root, name)) {
      files.push(name);
      evidence.push({ source: `file:${name}`, detail: `${name} is present` });
    }
  }

  return {
    hasDockerfile: files.some((f) => f.toLowerCase().startsWith('dockerfile')),
    hasCompose: files.some((f) => f.includes('compose')),
    files,
    evidence,
  };
}

/** Config files worth surfacing to later phases (build tooling, linting,
 * framework config) — presence only, no content interpretation here. */
const CONFIG_FILE_CANDIDATES = [
  'tsconfig.json',
  '.eslintrc.json',
  '.eslintrc.js',
  '.eslintrc.cjs',
  '.prettierrc',
  '.prettierrc.json',
  'babel.config.js',
  '.babelrc',
  'webpack.config.js',
  'vite.config.ts',
  'vite.config.js',
  'next.config.js',
  'next.config.mjs',
  'next.config.ts',
  'nest-cli.json',
  'jest.config.js',
  'jest.config.ts',
  'vitest.config.ts',
  '.npmrc',
  'nodemon.json',
];

export function detectConfigFiles(root: string): string[] {
  return CONFIG_FILE_CANDIDATES.filter((name) => fileExists(root, name));
}

/** Env files are reported by name only — contents are never read here,
 * since they commonly hold secrets and this phase does no secret handling. */
const ENV_FILE_CANDIDATES = [
  '.env',
  '.env.local',
  '.env.development',
  '.env.production',
  '.env.test',
  '.env.example',
  '.env.sample',
];

export function detectEnvFiles(root: string): string[] {
  return ENV_FILE_CANDIDATES.filter((name) => fileExists(root, name));
}
