/**
 * Bootstrap seeder.  `npm run db:seed`
 *
 * Creates the first administrator, which is the only account that cannot be
 * created through the API (registration requires an existing admin).
 *
 * Behaviour:
 *  - Idempotent: if the address already exists, nothing is changed.
 *  - There is no password. `SEED_ADMIN_EMAIL` must be the address of a Google
 *    account in an allowed domain; signing in with that Google account is how
 *    the administrator gets in. Anyone else from the domain who signs in first
 *    becomes a member, not an administrator.
 */

import { ROLES, USER_STATUS } from '@passm/shared';

// Importing the database module pulls in `config/env`, so the environment is
// validated before any seeding work begins.
import { closePool } from '../config/database';
import { env } from '../config/env';
import { logger } from '../config/logger';
import { roleRepository } from '../repositories/role.repository';
import { userRepository } from '../repositories/user.repository';

/**
 * Read a seed-only variable.
 *
 * Reading `process.env` directly is the sanctioned exception for CLI scripts:
 * these values are not part of the served application's configuration, so adding
 * them to `env.ts` would force every deployment to carry seed settings.
 */
function seedVar(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value === undefined || value === '' ? undefined : value;
}

async function main(): Promise<void> {
  const email = seedVar('SEED_ADMIN_EMAIL')?.toLowerCase();
  const firstName = seedVar('SEED_ADMIN_FIRST_NAME') ?? 'Platform';
  const lastName = seedVar('SEED_ADMIN_LAST_NAME') ?? 'Administrator';

  if (!email) {
    process.stderr.write(
      '\n[FATAL] Set SEED_ADMIN_EMAIL to the Google account that should be the first ' +
        'administrator, e.g.\n\n  SEED_ADMIN_EMAIL=you@123cfc.com npm run db:seed\n\n',
    );
    process.exit(1);
  }

  // A seeded address outside the allowed domains could never sign in.
  const domain = email.slice(email.lastIndexOf('@') + 1);
  if (env.google.allowedDomains.length > 0 && !env.google.allowedDomains.includes(domain)) {
    process.stderr.write(
      `\n[FATAL] ${email} is outside GOOGLE_ALLOWED_DOMAINS ` +
        `(${env.google.allowedDomains.join(', ')}), so it could never sign in.\n\n`,
    );
    process.exit(1);
  }

  if (await userRepository.existsByEmail(email)) {
    logger.info('Bootstrap administrator already exists; nothing to do', { email });
    return;
  }

  const roleId = await roleRepository.requireIdByName(ROLES.ADMIN);

  const userId = await userRepository.create({
    email,
    firstName,
    lastName,
    roleId,
    status: USER_STATUS.PENDING,
  });

  logger.info('Bootstrap administrator created', { userId, email, role: ROLES.ADMIN });

  process.stdout.write(
    [
      '',
      '='.repeat(78),
      '  BOOTSTRAP ADMINISTRATOR CREATED',
      '='.repeat(78),
      `  Email:  ${email}`,
      '',
      '  Sign in to the console with this Google account. There is no password.',
      '='.repeat(78),
      '',
    ].join('\n'),
  );
}

main()
  .then(async () => {
    await closePool();
    process.exit(0);
  })
  .catch(async (error: unknown) => {
    logger.error('Seeding failed', { error });
    await closePool().catch(() => undefined);
    process.exit(1);
  });
