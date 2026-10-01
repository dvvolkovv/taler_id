import { BadRequestException, NotFoundException } from '@nestjs/common';
import { GUARDS_METADATA, HTTP_CODE_METADATA } from '@nestjs/common/constants';
import { PartnerApiController } from './partner-api.controller';
import { PartnerKeyGuard } from './partner-key.guard';
import {
  PARTNER_RATE_BUCKET,
  PartnerRateLimitGuard,
} from './partner-rate-limit.guard';

describe('PartnerApiController', () => {
  const partner: any = { id: 'p1', slug: 'nadi' };
  const req: any = { partner, ip: '1.2.3.4' };
  let users: any;
  let codes: any;
  let contacts: any;
  let webhooks: any;
  let sink: any;
  let controller: PartnerApiController;

  beforeEach(() => {
    users = {
      provision: jest.fn(),
      getUser: jest.fn(),
      patchUser: jest.fn(),
      deleteUser: jest.fn(),
      issueToken: jest.fn(),
    };
    codes = { send: jest.fn(), verify: jest.fn() };
    contacts = { put: jest.fn(), remove: jest.fn() };
    webhooks = { deliver: jest.fn(), recentDeliveries: jest.fn() };
    sink = { list: jest.fn() };
    controller = new PartnerApiController(
      users,
      codes,
      contacts,
      webhooks,
      sink,
    );
  });

  it('passes deleteAccount=true through and validates the externalId', async () => {
    await controller.deleteUser(req, 'm-1', { deleteAccount: 'true' });
    expect(users.deleteUser).toHaveBeenCalledWith(
      partner,
      'm-1',
      true,
      '1.2.3.4',
    );
    await controller.deleteUser(req, 'm-1', {});
    expect(users.deleteUser).toHaveBeenLastCalledWith(
      partner,
      'm-1',
      false,
      '1.2.3.4',
    );
    expect(() => controller.getUser(req, 'bad id')).toThrow(
      BadRequestException,
    );
  });

  it('hands the six-digit code to the code service', async () => {
    await controller.verifyLinkCode(req, 'm-1', { code: '123456' });
    expect(codes.verify).toHaveBeenCalledWith(
      partner,
      'm-1',
      '123456',
      '1.2.3.4',
    );
  });

  it('is guarded by the partner key and limit instead of the global per-IP throttler', () => {
    expect(Reflect.getMetadata(GUARDS_METADATA, PartnerApiController)).toEqual([
      PartnerKeyGuard,
      PartnerRateLimitGuard,
    ]);
    for (const name of ['short', 'medium', 'long']) {
      expect(
        Reflect.getMetadata(`THROTTLER:SKIP${name}`, PartnerApiController),
      ).toBe(true);
    }
  });

  it('rate-limits the token route on its own bucket, by partner rather than per-IP', () => {
    expect(
      Reflect.getMetadata(
        PARTNER_RATE_BUCKET,
        PartnerApiController.prototype.token,
      ),
    ).toBe('token');
  });

  it('sends a ping and reports what the partner answered', async () => {
    webhooks.deliver.mockResolvedValue({
      eventId: 'evt_ping_x',
      type: 'ping',
      attempt: 1,
      delivered: true,
      status: 204,
      error: null,
      durationMs: 12,
      at: 'x',
    });
    await expect(controller.testWebhook(req)).resolves.toEqual({
      delivered: true,
      status: 204,
      durationMs: 12,
    });
    expect(webhooks.deliver).toHaveBeenCalledWith(
      'p1',
      expect.objectContaining({ type: 'ping' }),
    );
  });

  it('reports an undecryptable secret as a normal 200 answer, never a bare 500', async () => {
    webhooks.deliver.mockResolvedValue({
      eventId: 'evt_ping_x',
      type: 'ping',
      attempt: 1,
      delivered: false,
      status: null,
      error: 'secret_unreadable',
      durationMs: 0,
      partnerSlug: 'nadi',
      at: 'x',
    });
    await expect(controller.testWebhook(req)).resolves.toEqual({
      delivered: false,
      status: null,
      error: 'secret_unreadable',
      durationMs: 0,
    });
  });

  it('passes the deliveries limit through, defaulting to 50', async () => {
    await controller.deliveries(req, '10');
    expect(webhooks.recentDeliveries).toHaveBeenCalledWith('p1', 10);
    await controller.deliveries(req);
    expect(webhooks.recentDeliveries).toHaveBeenLastCalledWith('p1', 50);
    await controller.deliveries(req, 'not-a-number');
    expect(webhooks.recentDeliveries).toHaveBeenLastCalledWith('p1', 50);
  });

  describe('sinkEvents', () => {
    const savedSink = process.env.PARTNER_WEBHOOK_SINK;
    afterEach(() => {
      if (savedSink === undefined) delete process.env.PARTNER_WEBHOOK_SINK;
      else process.env.PARTNER_WEBHOOK_SINK = savedSink;
    });

    it('is 404 unless PARTNER_WEBHOOK_SINK=true', () => {
      delete process.env.PARTNER_WEBHOOK_SINK;
      expect(() => controller.sinkEvents(req)).toThrow(NotFoundException);
      expect(sink.list).not.toHaveBeenCalled();
    });

    it("lists this partner's own sink events once the sink is on", () => {
      process.env.PARTNER_WEBHOOK_SINK = 'true';
      sink.list.mockReturnValue([{ event: 'ping' }]);
      expect(controller.sinkEvents(req)).toEqual([{ event: 'ping' }]);
      expect(sink.list).toHaveBeenCalledWith('nadi');
    });
  });

  it('answers the documented HTTP status per route', () => {
    expect(
      Reflect.getMetadata(
        HTTP_CODE_METADATA,
        PartnerApiController.prototype.provision,
      ),
    ).toBe(200);
    expect(
      Reflect.getMetadata(
        HTTP_CODE_METADATA,
        PartnerApiController.prototype.token,
      ),
    ).toBe(200);
    expect(
      Reflect.getMetadata(
        HTTP_CODE_METADATA,
        PartnerApiController.prototype.sendLinkCode,
      ),
    ).toBe(200);
    expect(
      Reflect.getMetadata(
        HTTP_CODE_METADATA,
        PartnerApiController.prototype.verifyLinkCode,
      ),
    ).toBe(200);
    expect(
      Reflect.getMetadata(
        HTTP_CODE_METADATA,
        PartnerApiController.prototype.deleteUser,
      ),
    ).toBe(204);
  });
});
