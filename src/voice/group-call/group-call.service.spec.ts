import { Test } from '@nestjs/testing';
import { GroupCallService } from './group-call.service';
import { PrismaService } from '../../prisma/prisma.service';
import { VoiceService } from '../voice.service';
import { GroupCallGateway } from './group-call.gateway';
import { getQueueToken } from '@nestjs/bullmq';
import { ApnsService } from '../../common/apns.service';
import { FcmService } from '../../common/fcm.service';

describe('GroupCallService', () => {
  let service: GroupCallService;
  let prisma: any;
  let voice: any;
  let gateway: any;
  let queue: any;
  let apns: any;
  let fcm: any;

  beforeEach(async () => {
    prisma = {
      groupCall: { create: jest.fn(), findUnique: jest.fn(), update: jest.fn() },
      groupCallInvite: { createMany: jest.fn(), findMany: jest.fn(), update: jest.fn() },
      profile: {
        findUnique: jest.fn().mockResolvedValue({ firstName: 'Host', lastName: 'User', avatarUrl: null }),
      },
      $transaction: jest.fn(async (cb) => cb(prisma)),
    };
    voice = {
      generateGroupCallToken: jest.fn().mockResolvedValue({ token: 'jwt', livekitWsUrl: 'ws://lk' }),
      deleteRoom: jest.fn().mockResolvedValue(undefined),
    };
    gateway = {
      emitInvite: jest.fn(),
      emitStatus: jest.fn(),
      emitJoined: jest.fn(),
      emitLeft: jest.fn(),
      emitKicked: jest.fn(),
      emitMuteRequest: jest.fn(),
      emitHostChanged: jest.fn(),
      emitEnded: jest.fn(),
    };
    queue = { add: jest.fn(), remove: jest.fn() };
    apns = { sendGroupCallInvite: jest.fn().mockResolvedValue(undefined) };
    fcm = { sendGroupCallInvite: jest.fn().mockResolvedValue(undefined) };

    const moduleRef = await Test.createTestingModule({
      providers: [
        GroupCallService,
        { provide: PrismaService, useValue: prisma },
        { provide: VoiceService, useValue: voice },
        { provide: GroupCallGateway, useValue: gateway },
        { provide: getQueueToken('group-call-timeouts'), useValue: queue },
        { provide: ApnsService, useValue: apns },
        { provide: FcmService, useValue: fcm },
      ],
    }).compile();
    service = moduleRef.get(GroupCallService);
  });

  describe('createCall', () => {
    it('creates GroupCall + invites, schedules timeouts, sends push, returns token', async () => {
      const fakeCall = { id: 'gc-1', livekitRoomName: 'group-gc-1', hostUserId: 'host', status: 'LOBBY' };
      prisma.groupCall.create.mockResolvedValue({ id: 'gc-1', hostUserId: 'host', status: 'LOBBY', livekitRoomName: 'group-gc-1' });
      prisma.groupCall.update.mockResolvedValue(fakeCall);
      prisma.groupCallInvite.createMany.mockResolvedValue({ count: 2 });
      prisma.groupCallInvite.findMany.mockResolvedValue([
        { id: 'i1', userId: 'u1', status: 'CALLING' },
        { id: 'i2', userId: 'u2', status: 'CALLING' },
      ]);

      const result = await service.createCall('host', ['u1', 'u2']);

      expect(prisma.groupCall.create).toHaveBeenCalled();
      expect(prisma.groupCallInvite.createMany).toHaveBeenCalledWith({
        data: [
          { groupCallId: 'gc-1', userId: 'u1', invitedBy: 'host', status: 'CALLING' },
          { groupCallId: 'gc-1', userId: 'u2', invitedBy: 'host', status: 'CALLING' },
        ],
      });
      expect(queue.add).toHaveBeenCalledTimes(2);
      expect(apns.sendGroupCallInvite).toHaveBeenCalledTimes(2);
      expect(fcm.sendGroupCallInvite).toHaveBeenCalledTimes(2);
      expect(gateway.emitInvite).toHaveBeenCalledTimes(2);
      expect(result.livekitToken).toBe('jwt');
    });

    it('rejects empty invitee list', async () => {
      await expect(service.createCall('host', [])).rejects.toThrow();
    });

    it('rejects > 7 invitees (would exceed 8 cap with host)', async () => {
      await expect(service.createCall('host', ['u1', 'u2', 'u3', 'u4', 'u5', 'u6', 'u7', 'u8'])).rejects.toThrow();
    });

    it('rejects host self-invite', async () => {
      await expect(service.createCall('host', ['host', 'u1'])).rejects.toThrow();
    });

    it('rolls back if invite createMany throws', async () => {
      prisma.groupCall.create.mockResolvedValue({ id: 'gc-1', hostUserId: 'host', status: 'LOBBY', livekitRoomName: 'group-gc-1' });
      prisma.groupCallInvite.createMany.mockRejectedValue(new Error('db unique violation'));

      await expect(service.createCall('host', ['u1', 'u2'])).rejects.toThrow();

      // Push, queue, emit must NOT be called when DB write fails
      expect(queue.add).not.toHaveBeenCalled();
      expect(apns.sendGroupCallInvite).not.toHaveBeenCalled();
      expect(fcm.sendGroupCallInvite).not.toHaveBeenCalled();
      expect(gateway.emitInvite).not.toHaveBeenCalled();
    });

    it('two consecutive createCall invocations produce distinct GroupCalls (no idempotency)', async () => {
      // First call
      prisma.groupCall.create.mockResolvedValueOnce({ id: 'gc-1', hostUserId: 'host', status: 'LOBBY', livekitRoomName: 'group-gc-1' });
      prisma.groupCallInvite.findMany.mockResolvedValueOnce([{ id: 'i1', userId: 'u1', status: 'CALLING' }]);
      // Second call
      prisma.groupCall.create.mockResolvedValueOnce({ id: 'gc-2', hostUserId: 'host', status: 'LOBBY', livekitRoomName: 'group-gc-2' });
      prisma.groupCallInvite.findMany.mockResolvedValueOnce([{ id: 'i2', userId: 'u1', status: 'CALLING' }]);

      const r1 = await service.createCall('host', ['u1']);
      const r2 = await service.createCall('host', ['u1']);

      expect(r1.groupCall.id).not.toBe(r2.groupCall.id);
      expect(prisma.groupCall.create).toHaveBeenCalledTimes(2);
    });
  });

  describe('getActiveCallsForUser', () => {
    it('returns calls where user has CALLING/JOINED/LEFT/DECLINED invite and call is LOBBY/ACTIVE', async () => {
      const calls = [{ id: 'c1', status: 'ACTIVE', invites: [{ userId: 'u1', status: 'JOINED' }] }];
      prisma.groupCall.findMany = jest.fn().mockResolvedValue(calls);
      const result = await service.getActiveCallsForUser('u1');
      expect(prisma.groupCall.findMany).toHaveBeenCalledWith(expect.objectContaining({
        where: expect.objectContaining({
          status: { in: ['LOBBY', 'ACTIVE'] },
          invites: { some: { userId: 'u1', status: { in: ['CALLING', 'JOINED', 'LEFT', 'DECLINED'] } } },
        }),
      }));
      expect(result).toEqual(calls);
    });
  });

  describe('getCall', () => {
    it('throws NotFound if call missing', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue(null);
      await expect(service.getCall('xxx', 'u1')).rejects.toThrow();
    });

    it('throws Forbidden if user has no invite for the call', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({ id: 'c1', hostUserId: 'host', invites: [{ userId: 'u2' }] });
      await expect(service.getCall('c1', 'u1')).rejects.toThrow();
    });

    it('returns call if user has invite', async () => {
      const call = { id: 'c1', hostUserId: 'host', invites: [{ userId: 'u1' }] };
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue(call);
      expect(await service.getCall('c1', 'u1')).toEqual(call);
    });

    it('returns call if user is host (no invite needed)', async () => {
      const call = { id: 'c1', hostUserId: 'me', invites: [] };
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue(call);
      expect(await service.getCall('c1', 'me')).toEqual(call);
    });
  });

  describe('joinCall', () => {
    it('transitions invite CALLING→JOINED and call LOBBY→ACTIVE on first join', async () => {
      const call = {
        id: 'c1', status: 'LOBBY', livekitRoomName: 'group-c1', hostUserId: 'host',
        invites: [{ id: 'i1', userId: 'u1', status: 'CALLING' }],
      };
      prisma.groupCall.findUnique = jest.fn()
        .mockResolvedValueOnce(call)
        .mockResolvedValueOnce({ ...call, status: 'ACTIVE', invites: [{ ...call.invites[0], status: 'JOINED' }] });
      prisma.groupCallInvite.update = jest.fn().mockResolvedValue({ ...call.invites[0], status: 'JOINED' });
      prisma.groupCall.update = jest.fn().mockResolvedValue({ ...call, status: 'ACTIVE' });

      const r = await service.joinCall('c1', 'u1');

      expect(prisma.groupCallInvite.update).toHaveBeenCalledWith(expect.objectContaining({
        where: { groupCallId_userId: { groupCallId: 'c1', userId: 'u1' } },
        data: expect.objectContaining({ status: 'JOINED' }),
      }));
      expect(prisma.groupCall.update).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'c1' },
        data: expect.objectContaining({ status: 'ACTIVE' }),
      }));
      expect(queue.remove).toHaveBeenCalledWith('timeout-i1'); // pending timeout cancelled
      expect(r.livekitToken).toBe('jwt');
      expect(gateway.emitStatus).toHaveBeenCalled();
      expect(gateway.emitJoined).toHaveBeenCalled();
    });

    it('does NOT transition LOBBY→ACTIVE if already ACTIVE (second invitee joining)', async () => {
      const call = {
        id: 'c1', status: 'ACTIVE', livekitRoomName: 'group-c1', hostUserId: 'host',
        invites: [
          { id: 'i1', userId: 'u1', status: 'JOINED' },
          { id: 'i2', userId: 'u2', status: 'CALLING' },
        ],
      };
      prisma.groupCall.findUnique = jest.fn()
        .mockResolvedValueOnce(call)
        .mockResolvedValueOnce({ ...call, invites: [
          call.invites[0],
          { ...call.invites[1], status: 'JOINED' },
        ]});
      prisma.groupCallInvite.update = jest.fn();
      prisma.groupCall.update = jest.fn();

      await service.joinCall('c1', 'u2');

      expect(prisma.groupCallInvite.update).toHaveBeenCalled();
      expect(prisma.groupCall.update).not.toHaveBeenCalled(); // no LOBBY→ACTIVE
    });

    it('returns same token if already JOINED (idempotent)', async () => {
      const call = {
        id: 'c1', status: 'ACTIVE', livekitRoomName: 'group-c1', hostUserId: 'host',
        invites: [{ id: 'i1', userId: 'u1', status: 'JOINED' }],
      };
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue(call);
      const r = await service.joinCall('c1', 'u1');
      expect(prisma.groupCallInvite.update).not.toHaveBeenCalled();
      expect(r.livekitToken).toBeTruthy();
    });

    it('throws if call ENDED', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', status: 'ENDED', invites: [{ userId: 'u1', status: 'CALLING' }],
      });
      await expect(service.joinCall('c1', 'u1')).rejects.toThrow();
    });

    it('throws NotFound if call missing', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue(null);
      await expect(service.joinCall('xxx', 'u1')).rejects.toThrow();
    });

    it('throws Forbidden if user has no invite', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', status: 'ACTIVE', invites: [{ userId: 'u-other', status: 'JOINED' }],
      });
      await expect(service.joinCall('c1', 'u1')).rejects.toThrow();
    });
  });

  describe('declineCall', () => {
    it('marks invite DECLINED, broadcasts status', async () => {
      const call = {
        id: 'c1', status: 'LOBBY', livekitRoomName: 'group-c1', hostUserId: 'host',
        invites: [
          { id: 'i1', userId: 'u1', status: 'CALLING' },
          { id: 'i2', userId: 'u2', status: 'JOINED' },
        ],
      };
      prisma.groupCall.findUnique = jest.fn()
        .mockResolvedValueOnce(call)
        .mockResolvedValueOnce({ ...call, invites: [{ ...call.invites[0], status: 'DECLINED' }, call.invites[1]] });
      prisma.groupCallInvite.update = jest.fn();

      await service.declineCall('c1', 'u1');

      expect(prisma.groupCallInvite.update).toHaveBeenCalledWith(expect.objectContaining({
        data: expect.objectContaining({ status: 'DECLINED' }),
      }));
      expect(queue.remove).toHaveBeenCalledWith('timeout-i1');
      expect(gateway.emitStatus).toHaveBeenCalled();
    });

    it('ends call (timeout) if all invitees DECLINED/TIMEOUT and none JOINED', async () => {
      const call = {
        id: 'c1', status: 'LOBBY', livekitRoomName: 'group-c1', hostUserId: 'host',
        invites: [
          { id: 'i1', userId: 'u1', status: 'CALLING' },
          { id: 'i2', userId: 'u2', status: 'TIMEOUT' },
        ],
      };
      prisma.groupCall.findUnique = jest.fn()
        .mockResolvedValueOnce(call)
        .mockResolvedValueOnce({
          ...call,
          invites: [
            { id: 'i1', userId: 'u1', status: 'DECLINED' },
            { id: 'i2', userId: 'u2', status: 'TIMEOUT' },
          ],
        });
      prisma.groupCallInvite.update = jest.fn();
      prisma.groupCall.update = jest.fn().mockResolvedValue({ ...call, status: 'ENDED', endedReason: 'timeout' });
      prisma.groupCallInvite.findMany = jest.fn().mockResolvedValue([
        { userId: 'u1', status: 'DECLINED' },
        { userId: 'u2', status: 'TIMEOUT' },
      ]);
      voice.deleteRoom = jest.fn().mockResolvedValue(undefined);

      await service.declineCall('c1', 'u1');

      expect(prisma.groupCall.update).toHaveBeenCalledWith(expect.objectContaining({
        where: expect.objectContaining({ id: 'c1' }),
        data: expect.objectContaining({ status: 'ENDED', endedReason: 'timeout' }),
      }));
      expect(gateway.emitEnded).toHaveBeenCalled();
      expect(voice.deleteRoom).toHaveBeenCalledWith('group-c1');
    });

    it('does NOT end call if some still CALLING', async () => {
      const call = {
        id: 'c1', status: 'LOBBY', livekitRoomName: 'group-c1', hostUserId: 'host',
        invites: [
          { id: 'i1', userId: 'u1', status: 'CALLING' },
          { id: 'i2', userId: 'u2', status: 'CALLING' },
        ],
      };
      prisma.groupCall.findUnique = jest.fn()
        .mockResolvedValueOnce(call)
        .mockResolvedValueOnce({
          ...call,
          invites: [{ ...call.invites[0], status: 'DECLINED' }, call.invites[1]],
        });
      prisma.groupCallInvite.update = jest.fn();
      prisma.groupCall.update = jest.fn();

      await service.declineCall('c1', 'u1');

      expect(prisma.groupCall.update).not.toHaveBeenCalled();
    });

    it('throws 409 if invite already JOINED', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', status: 'ACTIVE', hostUserId: 'host',
        invites: [{ id: 'i1', userId: 'u1', status: 'JOINED' }],
      });
      await expect(service.declineCall('c1', 'u1')).rejects.toThrow();
    });

    it('idempotent if already DECLINED', async () => {
      const call = {
        id: 'c1', status: 'LOBBY', hostUserId: 'host',
        invites: [{ id: 'i1', userId: 'u1', status: 'DECLINED' }],
      };
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue(call);
      prisma.groupCallInvite.update = jest.fn();
      await service.declineCall('c1', 'u1');
      expect(prisma.groupCallInvite.update).not.toHaveBeenCalled();
    });

    it('throws NotFound if call missing', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue(null);
      await expect(service.declineCall('xxx', 'u1')).rejects.toThrow();
    });

    it('throws Forbidden if user has no invite', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', status: 'LOBBY', hostUserId: 'host',
        invites: [{ userId: 'u-other', status: 'CALLING' }],
      });
      await expect(service.declineCall('c1', 'u1')).rejects.toThrow();
    });
  });
});
