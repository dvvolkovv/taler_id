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
});
