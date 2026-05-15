import { PrismaService } from '../../prisma/prisma.service';

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Resolves a path parameter that can be either a userId (UUID) or a unique
 * username to the canonical userId. Used by public-link endpoints
 * (`GET /profile/:id`, `GET /messenger/contacts/check/:id`,
 * `GET /presence/:id`) so that share links of the form
 * `https://id.taler.tirol/u/<username>` work in addition to the UUID form.
 *
 * Returns `null` if the value is neither a known UUID-owning user nor a known
 * username; callers should treat null as "not found" (404 or domain
 * equivalent).
 */
export async function resolveUserIdOrUsername(
  prisma: PrismaService,
  raw: string,
): Promise<string | null> {
  if (!raw) return null;
  if (UUID_RE.test(raw)) {
    // Trust the UUID format; we don't pre-validate existence here because the
    // caller's own findUnique/select will fail naturally if the user is gone.
    return raw;
  }
  const user = await prisma.user.findUnique({
    where: { username: raw },
    select: { id: true },
  });
  return user?.id ?? null;
}
