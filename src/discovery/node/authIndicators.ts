import type { DetectedItem } from '../types.js';
import { hasDep, depVersion, type NodeAnalysisContext } from './context.js';

/**
 * Presence-only detection of authentication-related dependencies. This is
 * explicitly NOT a vulnerability or security-posture analysis — it only
 * records that an auth-related library is used, as later phases will need
 * this to scope their own analysis.
 */

const AUTH_DEP_NAMES = [
  'passport',
  'jsonwebtoken',
  'next-auth',
  'express-session',
  'bcrypt',
  'bcryptjs',
  'argon2',
  '@nestjs/passport',
  '@nestjs/jwt',
  'firebase-admin',
  'oauth2-server',
  'openid-client',
  'lucia',
  'clerk',
  '@clerk/nextjs',
  'auth0',
];

export function detectAuthIndicators(ctx: NodeAnalysisContext): DetectedItem[] {
  const results: DetectedItem[] = [];
  for (const depName of AUTH_DEP_NAMES) {
    if (!hasDep(ctx, depName)) continue;
    results.push({
      name: depName,
      confidence: 'high',
      evidence: [
        {
          source: 'package.json dependencies',
          detail: `"${depName}"${depVersion(ctx, depName) ? ` (${depVersion(ctx, depName)})` : ''} listed as a dependency`,
        },
      ],
    });
  }
  return results;
}
