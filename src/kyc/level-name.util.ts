/**
 * welID level names are project-scoped: `prj:<project>/<level-slug>`.
 *
 * An unprefixed name resolves inside welID's DEFAULT_PROJECT — on our instance
 * that is the foreign tenant `trientes`, so unprefixed calls silently borrow
 * someone else's level configuration and questionnaire. Passing `projectId` in
 * the accessTokens/sdk body also works but welID flags it as a legacy fallback
 * and asks integrators to move the project into the level name itself (#823).
 *
 * Idempotent: a name that already carries a prefix is returned untouched, so
 * operators may put the full wire form in SUMSUB_LEVEL_NAME if they prefer.
 */
export function prefixLevel(levelName: string, projectId: string): string {
  return levelName.startsWith('prj:')
    ? levelName
    : `prj:${projectId}/${levelName}`;
}
