import { ForbiddenException } from '@nestjs/common';
import { VoiceService } from './voice.service';

// Regression cover for the 2026-07-27 audit finding: POST /voice/rooms/:name/join
// issued a LiveKit token to any authenticated caller who knew a room name, and
// added them to participantIds on the way in.
describe('VoiceService.joinRoom entitlement', () => {
  let service: VoiceService;
  let prisma: any;

  const OWNER = 'abcdef12-3456-7890-abcd-ef1234567890';

  beforeEach(() => {
    prisma = {
      callLog: { findUnique: jest.fn(), update: jest.fn() },
      user: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'user-1',
          username: 'user1',
          profile: { firstName: 'A', lastName: 'B' },
        }),
      },
    };

    service = new VoiceService(
      prisma,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
    );
  });

  it('refuses a caller who was never invited', async () => {
    prisma.callLog.findUnique.mockResolvedValue({
      roomName: 'call-1',
      initiatorId: 'user-1',
      participantIds: ['user-1', 'user-2'],
    });

    await expect(service.joinRoom('call-1', 'intruder')).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('does not write an uninvited caller into the call log', async () => {
    prisma.callLog.findUnique.mockResolvedValue({
      roomName: 'call-1',
      initiatorId: 'user-1',
      participantIds: ['user-1'],
    });

    await expect(service.joinRoom('call-1', 'intruder')).rejects.toThrow();
    // Self-legitimising was half the problem: an intruder must not end up
    // looking like a participant in call history.
    expect(prisma.callLog.update).not.toHaveBeenCalled();
  });

  it('refuses when no call log exists for the room', async () => {
    prisma.callLog.findUnique.mockResolvedValue(null);

    await expect(service.joinRoom('call-unknown', 'user-1')).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('admits a user the invite flow already recorded', async () => {
    prisma.callLog.findUnique.mockResolvedValue({
      roomName: 'call-1',
      initiatorId: 'user-1',
      participantIds: ['user-1', 'invited-user'],
    });

    const res = await service.joinRoom('call-1', 'invited-user');
    expect(typeof res.token).toBe('string');
    expect(res.token.length).toBeGreaterThan(0);
  });

  it('admits the owner of a personal room without a call log', async () => {
    prisma.callLog.findUnique.mockResolvedValue(null);

    const res = await service.joinRoom(
      `personal-${OWNER.substring(0, 8)}-deadbeef`,
      OWNER,
    );
    expect(typeof res.token).toBe('string');
  });

  it("refuses a stranger at someone else's personal room", async () => {
    prisma.callLog.findUnique.mockResolvedValue(null);

    await expect(
      service.joinRoom('personal-abcdef12-deadbeef', 'stranger-uuid-here'),
    ).rejects.toThrow(ForbiddenException);
  });
});
