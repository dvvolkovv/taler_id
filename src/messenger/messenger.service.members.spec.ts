import { ForbiddenException } from '@nestjs/common';
import { MessengerService } from './messenger.service';

function make(
  conv: any,
  participant: any,
  participants: any[] = [],
  users: any[] = [],
) {
  const prisma: any = {
    conversationParticipant: {
      findUnique: jest.fn().mockResolvedValue(participant),
      findMany: jest.fn().mockResolvedValue(participants),
    },
    conversation: {
      findUnique: jest.fn().mockResolvedValue(conv),
    },
    user: {
      findMany: jest.fn().mockResolvedValue(users),
    },
  };
  const service = Object.create(MessengerService.prototype) as MessengerService;
  (service as any).prisma = prisma;
  return { service, prisma };
}

// Любой подписчик системного канала новостей (их тысячи — подписаны все
// пользователи) мог выкачать id+имя каждого подписчика через эту ручку,
// включая управляемые партнёром аккаунты, которых спека обещает не светить.
describe('MessengerService.getGroupMembers', () => {
  it('refuses a channel SUBSCRIBER', async () => {
    const { service, prisma } = make(
      { id: 'ch1', type: 'CHANNEL' },
      { role: 'SUBSCRIBER' },
    );
    await expect(service.getGroupMembers('ch1', 'u1')).rejects.toThrow(
      ForbiddenException,
    );
    expect(prisma.conversationParticipant.findMany).not.toHaveBeenCalled();
  });

  it('lets a channel ADMIN list members', async () => {
    const { service, prisma } = make(
      { id: 'ch1', type: 'CHANNEL' },
      { role: 'ADMIN' },
      [{ id: 'cp1', userId: 'u2', role: 'SUBSCRIBER', joinedAt: new Date() }],
      [{ id: 'u2', username: 'ivan', lastSeen: null, profile: null }],
    );
    const members = await service.getGroupMembers('ch1', 'u1');
    expect(members).toHaveLength(1);
    expect(members[0]).toMatchObject({ userId: 'u2', username: 'ivan' });
  });

  it('lets a channel OWNER list members', async () => {
    const { service } = make(
      { id: 'ch1', type: 'CHANNEL' },
      { role: 'OWNER' },
      [{ id: 'cp1', userId: 'u2', role: 'SUBSCRIBER', joinedAt: new Date() }],
      [{ id: 'u2', username: 'ivan', lastSeen: null, profile: null }],
    );
    await expect(service.getGroupMembers('ch1', 'u1')).resolves.toHaveLength(1);
  });

  it('lets any group member list members, unchanged', async () => {
    const { service } = make(
      { id: 'g1', type: 'GROUP' },
      { role: 'MEMBER' },
      [{ id: 'cp1', userId: 'u2', role: 'MEMBER', joinedAt: new Date() }],
      [{ id: 'u2', username: 'anna', lastSeen: null, profile: null }],
    );
    await expect(service.getGroupMembers('g1', 'u1')).resolves.toHaveLength(1);
  });
});
