import { ForbiddenException, BadRequestException } from '@nestjs/common';
import { MessengerService } from './messenger.service';

describe('MessengerService.unsubscribeFromChannel — system channel gate', () => {
  function makeService(conv: Record<string, any>) {
    const prisma: any = {
      conversation: {
        findUnique: jest.fn().mockResolvedValue(conv),
      },
      conversationParticipant: {
        findUnique: jest.fn().mockResolvedValue({
          conversationId: conv.id,
          userId: 'u1',
          role: 'SUBSCRIBER',
        }),
        delete: jest.fn().mockResolvedValue({}),
      },
    };
    const service = Object.create(MessengerService.prototype) as MessengerService;
    (service as any).prisma = prisma;
    return { service, prisma };
  }

  it('throws ForbiddenException when conversation is a system channel', async () => {
    const { service } = makeService({
      id: 'sys-chan',
      type: 'CHANNEL',
      isSystem: true,
    });
    await expect(
      service.unsubscribeFromChannel('sys-chan', 'u1'),
    ).rejects.toThrow(ForbiddenException);
  });

  it('does NOT throw ForbiddenException for a regular (non-system) channel', async () => {
    const { service } = makeService({
      id: 'reg-chan',
      type: 'CHANNEL',
      isSystem: false,
    });
    // Should proceed past the system-channel gate (no ForbiddenException thrown)
    await expect(
      service.unsubscribeFromChannel('reg-chan', 'u1'),
    ).resolves.toEqual({ ok: true });
  });
});
