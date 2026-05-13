-- One-time seed for the Taler ID Developer Portal's own OAuth client.
-- The SPA at /developers/ uses this clientId for its own login flow (dogfood).
-- Run once per database (DEV: taler_id_dev, PROD: taler_id) at first deploy
-- of Phase 4. Idempotent via ON CONFLICT.
--
-- Phase 4 spec: docs/superpowers/specs/2026-04-30-oauth-ui-kit-phase-4-developer-portal.md

INSERT INTO "OAuthClient" (
  "clientId",
  "clientSecret",
  "name",
  "redirectUris",
  "allowedScopes",
  "userId",
  "createdAt",
  "updatedAt"
)
VALUES (
  'taler-id-developers',
  encode(gen_random_bytes(32), 'base64'),
  'Taler ID Developer Portal',
  ARRAY[
    'https://id.taler.tirol/developers/',
    'https://staging.id.taler.tirol/developers/'
  ],
  ARRAY['openid', 'profile', 'email', 'offline_access'],
  NULL,
  now(),
  now()
)
ON CONFLICT ("clientId") DO NOTHING;
