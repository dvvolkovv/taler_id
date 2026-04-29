import { Test } from '@nestjs/testing';
import { GroupCallService } from './group-call.service';
import { PrismaService } from '../../prisma/prisma.service';
import { VoiceService } from '../voice.service';
import { GroupCallGateway } from './group-call.gateway';
import { getQueueToken } from '@nestjs/bullmq';
import { ApnsService } from '../../common/apns.service';
import { FcmService } from '../../common/fcm.service';
import { RedisService } from '../../redis/redis.service';

describe('GroupCallService', () => {
  let service: GroupCallService;
  let prisma: any;
  let voice: any;
  let gateway: any;
  let queue: any;
  let apns: any;
  let fcm: any;
  let redis: any;

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
    redis = {
      getClient: jest.fn(() => ({
        set: jest.fn().mockResolvedValue('OK'),
      })),
    };

    const moduleRef = await Test.createTestingModule({
      providers: [
        GroupCallService,
        { provide: PrismaService, useValue: prisma },
        { provide: VoiceService, useValue: voice },
        { provide: GroupCallGateway, useValue: gateway },
        { provide: getQueueToken('group-call-timeouts'), useValue: queue },
        { provide: ApnsService, useValue: apns },
        { provide: FcmService, useValue: fcm },
        { provide: RedisService, useValue: redis },
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

  describe('leaveCall', () => {
    it('marks invite LEFT, broadcasts status (non-host leaves)', async () => {
      const call = {
        id: 'c1', status: 'ACTIVE', hostUserId: 'host', livekitRoomName: 'group-c1',
        invites: [
          { id: 'i1', userId: 'u1', status: 'JOINED', joinedAt: new Date('2026-04-29T10:00:00Z') },
          { id: 'i2', userId: 'u2', status: 'JOINED', joinedAt: new Date('2026-04-29T10:01:00Z') },
        ],
      };
      prisma.groupCall.findUnique = jest.fn()
        .mockResolvedValueOnce(call)
        .mockResolvedValueOnce({
          ...call,
          invites: [{ ...call.invites[0], status: 'LEFT', leftAt: new Date() }, call.invites[1]],
        });
      prisma.groupCallInvite.update = jest.fn();
      prisma.groupCall.update = jest.fn();

      await service.leaveCall('c1', 'u1');

      expect(prisma.groupCallInvite.update).toHaveBeenCalledWith(expect.objectContaining({
        where: { groupCallId_userId: { groupCallId: 'c1', userId: 'u1' } },
        data: expect.objectContaining({ status: 'LEFT' }),
      }));
      expect(prisma.groupCall.update).not.toHaveBeenCalled(); // no host change since u1 isn't host
      expect(gateway.emitLeft).toHaveBeenCalled();
    });

    it('transfers host to next JOINED (joinedAt asc) when host leaves', async () => {
      const call = {
        id: 'c1', status: 'ACTIVE', hostUserId: 'host', livekitRoomName: 'group-c1',
        invites: [
          { id: 'i1', userId: 'u1', status: 'JOINED', joinedAt: new Date('2026-04-29T10:00:00Z') },
          { id: 'i2', userId: 'u2', status: 'JOINED', joinedAt: new Date('2026-04-29T10:01:00Z') },
        ],
      };
      prisma.groupCall.findUnique = jest.fn()
        .mockResolvedValueOnce(call)
        .mockResolvedValueOnce(call); // refetch returns same set (host's invite doesn't exist as a row)
      prisma.groupCall.update = jest.fn();

      await service.leaveCall('c1', 'host');

      expect(prisma.groupCall.update).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'c1' },
        data: expect.objectContaining({ hostUserId: 'u1' }),
      }));
      expect(gateway.emitHostChanged).toHaveBeenCalledWith(
        expect.any(Array),
        expect.objectContaining({ groupCallId: 'c1', newHostUserId: 'u1' }),
      );
    });

    it('ends call (all_left) when last JOINED leaves', async () => {
      const call = {
        id: 'c1', status: 'ACTIVE', hostUserId: 'host', livekitRoomName: 'group-c1',
        invites: [{ id: 'i1', userId: 'u1', status: 'JOINED', joinedAt: new Date() }],
      };
      prisma.groupCall.findUnique = jest.fn()
        .mockResolvedValueOnce(call)
        .mockResolvedValueOnce({
          ...call,
          invites: [{ ...call.invites[0], status: 'LEFT', leftAt: new Date() }],
        });
      prisma.groupCallInvite.update = jest.fn();
      prisma.groupCallInvite.findMany = jest.fn().mockResolvedValue([
        { userId: 'u1', status: 'LEFT' },
      ]);
      prisma.groupCall.update = jest.fn().mockResolvedValue({
        ...call, status: 'ENDED', endedReason: 'all_left',
      });
      voice.deleteRoom = jest.fn().mockResolvedValue(undefined);

      await service.leaveCall('c1', 'u1');

      expect(prisma.groupCall.update).toHaveBeenCalledWith(expect.objectContaining({
        data: expect.objectContaining({ status: 'ENDED', endedReason: 'all_left' }),
      }));
      expect(gateway.emitEnded).toHaveBeenCalled();
    });

    it('idempotent if already LEFT', async () => {
      const call = {
        id: 'c1', status: 'ACTIVE', hostUserId: 'host', livekitRoomName: 'group-c1',
        invites: [{ id: 'i1', userId: 'u1', status: 'LEFT', joinedAt: new Date() }],
      };
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue(call);
      prisma.groupCallInvite.update = jest.fn();

      await service.leaveCall('c1', 'u1');

      expect(prisma.groupCallInvite.update).not.toHaveBeenCalled();
    });

    it('returns silently if call already ENDED (race-safe)', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', status: 'ENDED', hostUserId: 'host', invites: [],
      });
      prisma.groupCallInvite.update = jest.fn();

      await service.leaveCall('c1', 'u1');

      expect(prisma.groupCallInvite.update).not.toHaveBeenCalled();
    });

    it('throws NotFound if call missing', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue(null);
      await expect(service.leaveCall('xxx', 'u1')).rejects.toThrow();
    });

    it('throws Forbidden if user is neither host nor invitee', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', status: 'ACTIVE', hostUserId: 'host',
        invites: [{ userId: 'u-other', status: 'JOINED' }],
      });
      await expect(service.leaveCall('c1', 'u1')).rejects.toThrow();
    });

    it('host leaves alone (no other JOINED) → call ENDED, no transfer', async () => {
      const call = {
        id: 'c1', status: 'ACTIVE', hostUserId: 'host', livekitRoomName: 'group-c1',
        invites: [
          { id: 'i1', userId: 'u1', status: 'DECLINED', joinedAt: null },
          { id: 'i2', userId: 'u2', status: 'TIMEOUT', joinedAt: null },
        ],
      };
      prisma.groupCall.findUnique = jest.fn()
        .mockResolvedValueOnce(call)
        .mockResolvedValueOnce(call);
      // Single mock catches both possible writes (host transfer skipped + endCall ENDED).
      prisma.groupCall.update = jest.fn().mockResolvedValue({
        ...call, status: 'ENDED', endedReason: 'all_left',
      });
      prisma.groupCallInvite.findMany = jest.fn().mockResolvedValue(call.invites);
      voice.deleteRoom = jest.fn().mockResolvedValue(undefined);

      await service.leaveCall('c1', 'host');

      // Host should NOT be transferred (no JOINED candidates).
      expect(gateway.emitHostChanged).not.toHaveBeenCalled();
      // Call should be ENDED.
      expect(prisma.groupCall.update).toHaveBeenCalledWith(expect.objectContaining({
        data: expect.objectContaining({ status: 'ENDED', endedReason: 'all_left' }),
      }));
    });
  });

  describe('inviteMore (host only, capacity check)', () => {
    it('rejects if non-host', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', hostUserId: 'host', status: 'ACTIVE', invites: [],
      });
      await expect(service.inviteMore('c1', 'someone-else', ['u9'])).rejects.toThrow();
    });

    it('rejects if (JOINED + CALLING + new) > 8', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', hostUserId: 'host', status: 'ACTIVE', livekitRoomName: 'group-c1',
        invites: [
          { userId: 'u1', status: 'JOINED' }, { userId: 'u2', status: 'JOINED' },
          { userId: 'u3', status: 'JOINED' }, { userId: 'u4', status: 'JOINED' },
          { userId: 'u5', status: 'JOINED' }, { userId: 'u6', status: 'JOINED' },
          { userId: 'u7', status: 'CALLING' },
        ],
      });
      // Host (1) + 6 JOINED + 1 CALLING = 8. Adding 1 more would overflow.
      await expect(service.inviteMore('c1', 'host', ['u9'])).rejects.toThrow();
    });

    it('inserts invites for new userIds, skips duplicates (already JOINED/CALLING)', async () => {
      const call = {
        id: 'c1', hostUserId: 'host', status: 'ACTIVE', livekitRoomName: 'group-c1',
        invites: [{ userId: 'u1', status: 'JOINED' }],
      };
      prisma.groupCall.findUnique = jest.fn()
        .mockResolvedValueOnce(call)
        .mockResolvedValueOnce({
          ...call,
          invites: [
            { userId: 'u1', status: 'JOINED' },
            { id: 'inew', userId: 'u2', status: 'CALLING' },
          ],
        });
      prisma.groupCallInvite.createMany = jest.fn();
      prisma.groupCallInvite.findMany = jest.fn().mockResolvedValue([{ id: 'inew', userId: 'u2', status: 'CALLING' }]);
      prisma.profile.findUnique = jest.fn().mockResolvedValue({ firstName: 'H', lastName: 'O', avatarUrl: null });

      const result = await service.inviteMore('c1', 'host', ['u1', 'u2']); // u1 already JOINED → skip

      expect(prisma.groupCallInvite.createMany).toHaveBeenCalledWith({
        data: [{ groupCallId: 'c1', userId: 'u2', invitedBy: 'host', status: 'CALLING' }],
      });
      expect(queue.add).toHaveBeenCalledTimes(1);
      expect(apns.sendGroupCallInvite).toHaveBeenCalledWith('u2', expect.anything());
      expect(result.added).toBe(1);
    });

    it('rejects ENDED call', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', hostUserId: 'host', status: 'ENDED', invites: [],
      });
      await expect(service.inviteMore('c1', 'host', ['u9'])).rejects.toThrow();
    });
  });

  describe('kick (host only)', () => {
    it('rejects if non-host', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', hostUserId: 'host', invites: [{ userId: 'u1', status: 'JOINED' }],
      });
      await expect(service.kick('c1', 'someone', 'u1')).rejects.toThrow();
    });

    it('rejects if host kicks self', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', hostUserId: 'host', invites: [],
      });
      await expect(service.kick('c1', 'host', 'host')).rejects.toThrow();
    });

    it('marks LEFT, calls LiveKit removeParticipant, broadcasts kicked + status', async () => {
      // Two JOINED invitees: kicking u1 leaves u2 still JOINED, so the call
      // remains ACTIVE and `endCallIfDeserted` is a no-op. Keeps this test
      // focused on the kick action itself; the desertion path is exercised
      // by the leaveCall suite.
      const call = {
        id: 'c1', hostUserId: 'host', livekitRoomName: 'group-c1', status: 'ACTIVE',
        invites: [
          { id: 'i1', userId: 'u1', status: 'JOINED' },
          { id: 'i2', userId: 'u2', status: 'JOINED' },
        ],
      };
      prisma.groupCall.findUnique = jest.fn()
        .mockResolvedValueOnce(call)
        .mockResolvedValueOnce({
          ...call,
          invites: [{ ...call.invites[0], status: 'LEFT' }, call.invites[1]],
        });
      prisma.groupCallInvite.update = jest.fn();
      voice.removeParticipant = jest.fn().mockResolvedValue(undefined);

      await service.kick('c1', 'host', 'u1');

      expect(voice.removeParticipant).toHaveBeenCalledWith('group-c1', 'u1');
      expect(gateway.emitKicked).toHaveBeenCalledWith('u1', expect.objectContaining({ groupCallId: 'c1', by: 'host' }));
      expect(gateway.emitStatus).toHaveBeenCalled();
    });

    it('idempotent if target already LEFT', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', hostUserId: 'host', livekitRoomName: 'group-c1',
        invites: [{ id: 'i1', userId: 'u1', status: 'LEFT' }],
      });
      prisma.groupCallInvite.update = jest.fn();
      voice.removeParticipant = jest.fn();

      await service.kick('c1', 'host', 'u1');

      expect(prisma.groupCallInvite.update).not.toHaveBeenCalled();
    });

    it('throws NotFound if target has no invite row', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', hostUserId: 'host', livekitRoomName: 'group-c1',
        invites: [{ userId: 'u-other', status: 'JOINED' }],
      });
      await expect(service.kick('c1', 'host', 'u1')).rejects.toThrow();
    });

    it('ends call (all_left) if kicking the last JOINED leaves nobody', async () => {
      const call = {
        id: 'c1', hostUserId: 'host', livekitRoomName: 'group-c1', status: 'ACTIVE',
        invites: [{ id: 'i1', userId: 'u1', status: 'JOINED', joinedAt: new Date() }],
      };
      prisma.groupCall.findUnique = jest.fn()
        .mockResolvedValueOnce(call)
        .mockResolvedValueOnce({
          ...call,
          invites: [{ ...call.invites[0], status: 'LEFT' }],
        });
      prisma.groupCallInvite.update = jest.fn();
      prisma.groupCallInvite.findMany = jest.fn().mockResolvedValue([
        { userId: 'u1', status: 'LEFT' },
      ]);
      prisma.groupCall.update = jest.fn().mockResolvedValue({
        ...call, status: 'ENDED', endedReason: 'all_left',
      });
      voice.removeParticipant = jest.fn().mockResolvedValue(undefined);
      voice.deleteRoom = jest.fn().mockResolvedValue(undefined);

      await service.kick('c1', 'host', 'u1');

      expect(prisma.groupCall.update).toHaveBeenCalledWith(expect.objectContaining({
        data: expect.objectContaining({ status: 'ENDED', endedReason: 'all_left' }),
      }));
      expect(gateway.emitEnded).toHaveBeenCalled();
    });
  });

  describe('muteAll (host only, rate-limited)', () => {
    it('rejects if non-host', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', hostUserId: 'host', invites: [],
      });
      await expect(service.muteAll('c1', 'someone')).rejects.toThrow();
    });

    it('broadcasts mute_request to all JOINED participants except host', async () => {
      const call = {
        id: 'c1', hostUserId: 'host', livekitRoomName: 'group-c1', status: 'ACTIVE',
        invites: [
          { userId: 'u1', status: 'JOINED' },
          { userId: 'u2', status: 'JOINED' },
          { userId: 'u3', status: 'CALLING' }, // not yet in room — should NOT receive
        ],
      };
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue(call);

      await service.muteAll('c1', 'host');

      expect(gateway.emitMuteRequest).toHaveBeenCalledWith(
        ['u1', 'u2'],
        expect.objectContaining({ groupCallId: 'c1', by: 'host' }),
      );
    });

    it('rejects if rate-limited (Redis NX returns null)', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', hostUserId: 'host', invites: [{ userId: 'u1', status: 'JOINED' }],
      });
      // Override redis client.set to simulate rate-limit hit (key already exists)
      redis.getClient = jest.fn(() => ({ set: jest.fn().mockResolvedValue(null) }));

      await expect(service.muteAll('c1', 'host')).rejects.toThrow();
    });
  });

  describe('handleInviteTimeout', () => {
    it('marks invite TIMEOUT if still CALLING, broadcasts, may end call', async () => {
      const invite = { id: 'i1', groupCallId: 'c1', userId: 'u1', status: 'CALLING' };
      prisma.groupCallInvite.findUnique = jest.fn().mockResolvedValue(invite);
      prisma.groupCallInvite.update = jest.fn();
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', status: 'LOBBY', hostUserId: 'host', livekitRoomName: 'group-c1',
        invites: [{ ...invite, status: 'TIMEOUT' }],
      });
      // Single-invitee desertion path: endCallIfDeserted → endCall calls these.
      // We don't assert on them here (the dedicated "ends LOBBY call" test does);
      // we just need the chain to not blow up on undefined.
      prisma.groupCall.update = jest.fn().mockResolvedValue({
        id: 'c1', hostUserId: 'host', livekitRoomName: 'group-c1', status: 'ENDED',
      });
      prisma.groupCallInvite.findMany = jest.fn().mockResolvedValue([
        { userId: 'u1', status: 'TIMEOUT' },
      ]);
      voice.deleteRoom = jest.fn().mockResolvedValue(undefined);

      await service.handleInviteTimeout('i1');

      expect(prisma.groupCallInvite.update).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'i1' },
        data: expect.objectContaining({ status: 'TIMEOUT' }),
      }));
      expect(gateway.emitStatus).toHaveBeenCalled();
    });

    it('no-op if invite already JOINED', async () => {
      prisma.groupCallInvite.findUnique = jest.fn().mockResolvedValue({
        id: 'i1', groupCallId: 'c1', userId: 'u1', status: 'JOINED',
      });
      prisma.groupCallInvite.update = jest.fn();
      await service.handleInviteTimeout('i1');
      expect(prisma.groupCallInvite.update).not.toHaveBeenCalled();
    });

    it('no-op if invite already DECLINED', async () => {
      prisma.groupCallInvite.findUnique = jest.fn().mockResolvedValue({
        id: 'i1', groupCallId: 'c1', userId: 'u1', status: 'DECLINED',
      });
      prisma.groupCallInvite.update = jest.fn();
      await service.handleInviteTimeout('i1');
      expect(prisma.groupCallInvite.update).not.toHaveBeenCalled();
    });

    it('no-op if invite not found (missing)', async () => {
      prisma.groupCallInvite.findUnique = jest.fn().mockResolvedValue(null);
      prisma.groupCallInvite.update = jest.fn();
      await service.handleInviteTimeout('xxx');
      expect(prisma.groupCallInvite.update).not.toHaveBeenCalled();
    });

    it('ends LOBBY call if last CALLING times out and no one JOINED', async () => {
      const invite = { id: 'i1', groupCallId: 'c1', userId: 'u1', status: 'CALLING' };
      prisma.groupCallInvite.findUnique = jest.fn().mockResolvedValue(invite);
      prisma.groupCallInvite.update = jest.fn();
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', status: 'LOBBY', hostUserId: 'host', livekitRoomName: 'group-c1',
        invites: [{ ...invite, status: 'TIMEOUT' }], // single invitee, now TIMEOUT
      });
      prisma.groupCall.update = jest.fn().mockResolvedValue({
        id: 'c1', hostUserId: 'host', livekitRoomName: 'group-c1', status: 'ENDED',
      });
      prisma.groupCallInvite.findMany = jest.fn().mockResolvedValue([{ userId: 'u1', status: 'TIMEOUT' }]);
      voice.deleteRoom = jest.fn().mockResolvedValue(undefined);

      await service.handleInviteTimeout('i1');

      expect(prisma.groupCall.update).toHaveBeenCalledWith(expect.objectContaining({
        data: expect.objectContaining({ status: 'ENDED', endedReason: 'timeout' }),
      }));
      expect(gateway.emitEnded).toHaveBeenCalled();
    });
  });

  describe('forceEnd (host only)', () => {
    it('rejects if non-host', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', hostUserId: 'host', status: 'ACTIVE', invites: [],
      });
      await expect(service.forceEnd('c1', 'someone')).rejects.toThrow();
    });

    it('ends call with reason=host_ended', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', hostUserId: 'host', status: 'ACTIVE', livekitRoomName: 'group-c1',
        invites: [{ userId: 'u1', status: 'JOINED' }],
      });
      prisma.groupCall.update = jest.fn().mockResolvedValue({
        id: 'c1', hostUserId: 'host', livekitRoomName: 'group-c1',
      });
      prisma.groupCallInvite.findMany = jest.fn().mockResolvedValue([]);
      voice.deleteRoom = jest.fn().mockResolvedValue(undefined);

      await service.forceEnd('c1', 'host');

      expect(prisma.groupCall.update).toHaveBeenCalledWith(expect.objectContaining({
        data: expect.objectContaining({ status: 'ENDED', endedReason: 'host_ended' }),
      }));
      expect(gateway.emitEnded).toHaveBeenCalled();
    });

    it('idempotent if already ENDED', async () => {
      prisma.groupCall.findUnique = jest.fn().mockResolvedValue({
        id: 'c1', hostUserId: 'host', status: 'ENDED', invites: [],
      });
      prisma.groupCall.update = jest.fn();

      await service.forceEnd('c1', 'host');

      expect(prisma.groupCall.update).not.toHaveBeenCalled();
    });
  });

  describe('handleZombieEnd', () => {
    it('delegates to endCall (transitions ENDED)', async () => {
      const call = {
        id: 'c1', hostUserId: 'host', livekitRoomName: 'group-c1', status: 'LOBBY',
      };
      prisma.groupCall.update = jest.fn().mockResolvedValue(call);
      prisma.groupCallInvite.findMany = jest.fn().mockResolvedValue([]);
      voice.deleteRoom = jest.fn().mockResolvedValue(undefined);

      await service.handleZombieEnd('c1', 'timeout');

      expect(prisma.groupCall.update).toHaveBeenCalledWith(expect.objectContaining({
        data: expect.objectContaining({ status: 'ENDED', endedReason: 'timeout' }),
      }));
      expect(gateway.emitEnded).toHaveBeenCalled();
    });

    it('handles all_left reason', async () => {
      const call = {
        id: 'c1', hostUserId: 'host', livekitRoomName: 'group-c1', status: 'ACTIVE',
      };
      prisma.groupCall.update = jest.fn().mockResolvedValue(call);
      prisma.groupCallInvite.findMany = jest.fn().mockResolvedValue([]);
      voice.deleteRoom = jest.fn().mockResolvedValue(undefined);

      await service.handleZombieEnd('c1', 'all_left');

      expect(prisma.groupCall.update).toHaveBeenCalledWith(expect.objectContaining({
        data: expect.objectContaining({ endedReason: 'all_left' }),
      }));
    });
  });
});
