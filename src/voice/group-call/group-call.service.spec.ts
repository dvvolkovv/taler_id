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
      user: { findUnique: jest.fn().mockResolvedValue({ id: 'host', displayName: 'Host User' }) },
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
  });
});
