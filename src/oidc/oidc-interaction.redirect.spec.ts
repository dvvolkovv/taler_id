import { OidcInteractionController } from './oidc-interaction.controller';

// Regression cover for the Linkeon integration failure (2026-08-03): the
// consent page submits over `fetch`, and finishing an interaction answered with
// a 303 whose chain ends at the client's own callback. Following that
// cross-origin hop from `fetch` is blocked by our CSP `connect-src`, so "Allow"
// silently did nothing for every client with an external callback — the flow
// only ever completed for curl, which ignores CSP.
//
// Callers that ask for JSON now get the URL to navigate to; everyone else keeps
// the redirect.
describe('OidcInteractionController interaction completion', () => {
  let controller: OidcInteractionController;
  let oidc: any;

  const RESULT = { consent: { grantId: 'grant-1' } };
  const RETURN_TO = 'https://api.talerid.io/oauth/auth/abc123';

  // The method under test is private; this is the narrow seam.
  const finish = (req: any, res: any) =>
    (controller as any).finish(req, res, RESULT);

  const res = () => ({ json: jest.fn() });

  beforeEach(() => {
    oidc = {
      finishInteraction: jest.fn(async () => undefined),
      resolveInteractionRedirect: jest.fn(async () => RETURN_TO),
    };
    controller = new OidcInteractionController(oidc, {} as any, {} as any);
  });

  it('hands the URL back as JSON when the caller asks for JSON', async () => {
    const r = res();
    await finish({ headers: { accept: 'application/json' } }, r);

    expect(r.json).toHaveBeenCalledWith({ redirectTo: RETURN_TO });
    expect(oidc.finishInteraction).not.toHaveBeenCalled();
  });

  it('still redirects a browser navigation', async () => {
    const r = res();
    await finish({ headers: { accept: 'text/html,application/xhtml+xml' } }, r);

    expect(oidc.finishInteraction).toHaveBeenCalled();
    expect(r.json).not.toHaveBeenCalled();
  });

  it('redirects when the caller states no preference', async () => {
    // curl and server-to-server callers send */* or nothing at all, and follow
    // redirects natively — changing their shape would break them.
    for (const headers of [{ accept: '*/*' }, {}, undefined]) {
      const r = res();
      oidc.finishInteraction.mockClear();
      await finish({ headers }, r);

      expect(oidc.finishInteraction).toHaveBeenCalled();
      expect(r.json).not.toHaveBeenCalled();
    }
  });

  it('accepts a compound Accept header that includes JSON', async () => {
    const r = res();
    await finish({ headers: { accept: 'application/json, text/plain, */*' } }, r);

    expect(r.json).toHaveBeenCalledWith({ redirectTo: RETURN_TO });
  });
});
