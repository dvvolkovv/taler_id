import { ForbiddenException } from '@nestjs/common';
import { MessengerAuthGuard } from './messenger-auth.guard';
import { MessengerController } from './messenger.controller';
import { PARTNER_ALLOWED_KEY, PartnerAllowedOptions } from './partner-allowed.decorator';
import { PARTNER_CONVERSATION_TYPES } from '../partner-core/partner.constants';

/** Ровно этот набор обработчиков открыт партнёрам — спека, раздел «Что открыто». */
const EXPECTED: Record<string, PartnerAllowedOptions> = {
  create: {},
  list: {},
  sync: {},
  readState: {},
  conversationReadState: { conversationParam: 'id' },
  messages: { conversationParam: 'id' },
  readers: { messageParam: 'id' },
  sharedMedia: { conversationParam: 'id' },
  createGroup: {},
  getMembers: { conversationParam: 'id' },
  addMembers: { conversationParam: 'id' },
  removeMember: { conversationParam: 'id' },
  changeRole: { conversationParam: 'id' },
  updateGroup: { conversationParam: 'id' },
  muteConversation: { conversationParam: 'id' },
  unmuteConversation: { conversationParam: 'id' },
  leaveGroup: { conversationParam: 'id' },
  deleteGroup: { conversationParam: 'id' },
  getContactStatus: {},
  blockUser: {},
  unblockUser: {},
  isBlocked: {},
  searchMessages: {},
  uploadFile: {},
  getFileUrl: {},
  initChunkedUpload: {},
  uploadChunk: {},
  completeChunkedUpload: {},
  abortChunkedUpload: {},
  linkPreview: {},
  forwardMessages: { conversationParam: 'id' },
  pinMessage: { conversationParam: 'id', messageParam: 'msgId' },
  unpinMessage: { conversationParam: 'id', messageParam: 'msgId' },
  listPinned: { conversationParam: 'id' },
  unpinAll: { conversationParam: 'id' },
  dismissPins: { conversationParam: 'id' },
  getThread: { conversationParam: 'convId', messageParam: 'msgId' },
  sendThreadReply: { conversationParam: 'convId', messageParam: 'msgId' },
};

function partnerAllowlist(): Record<string, PartnerAllowedOptions> {
  const proto = MessengerController.prototype as any;
  const out: Record<string, PartnerAllowedOptions> = {};
  for (const name of Object.getOwnPropertyNames(proto)) {
    if (name === 'constructor') continue;
    const meta = Reflect.getMetadata(PARTNER_ALLOWED_KEY, proto[name]);
    if (meta) out[name] = meta;
  }
  return out;
}

describe('MessengerController for partner tokens', () => {
  it('opens exactly the agreed handlers to partners', () => {
    expect(partnerAllowlist()).toEqual(EXPECTED);
  });

  it('guards the whole controller with MessengerAuthGuard', () => {
    expect(Reflect.getMetadata('__guards__', MessengerController)).toEqual([MessengerAuthGuard]);
  });

  describe('lists and groups', () => {
    const partnerUser = { sub: 'u1', partner: { partnerId: 'p1' } };
    const nativeUser = { sub: 'u1' };
    let service: any;
    let scope: any;
    let gateway: any;
    let controller: MessengerController;

    beforeEach(() => {
      service = {
        getConversations: jest.fn().mockResolvedValue([
          { id: 'c1', type: 'DIRECT' },
          { id: 'c2', type: 'CHANNEL' },
          { id: 'c3', type: 'GROUP' },
          { id: 'c4', type: 'SAVED' },
        ]),
        sync: jest.fn().mockResolvedValue({
          messages: [{ id: 'm1', conversationId: 'c1' }, { id: 'm2', conversationId: 'c2' }],
          nextCursor: 'x',
          hasMore: false,
        }),
        readStateForUser: jest.fn().mockResolvedValue({ conversations: [{ conversationId: 'c1' }, { conversationId: 'c2' }] }),
        searchMessages: jest.fn().mockResolvedValue([{ id: 'm1', conversationId: 'c1' }, { id: 'm2', conversationId: 'c4' }]),
        createGroupConversation: jest.fn().mockResolvedValue({ id: 'g1', participantIds: ['u1', 'u2'] }),
        addGroupMembers: jest.fn().mockResolvedValue([]),
        changeGroupMemberRole: jest.fn().mockResolvedValue({ userId: 'u3', newRole: 'ADMIN' }),
        updateGroupInfo: jest.fn().mockResolvedValue({ id: 'g1', name: 'New name' }),
        leaveGroup: jest.fn().mockResolvedValue(undefined),
        forwardMessages: jest.fn().mockResolvedValue([]),
        getUserDisplayName: jest.fn().mockResolvedValue('Name'),
      };
      scope = {
        visibleConversationIds: jest.fn().mockResolvedValue(new Set(['c1', 'c3'])),
        assertAllContacts: jest.fn().mockResolvedValue(undefined),
        assertMessages: jest.fn().mockResolvedValue(undefined),
      };
      gateway = {
        emitToUser: jest.fn(),
        emitToUserInConversation: jest.fn(),
        emitToConversationParticipantsInConversation: jest.fn(),
        evictFromConversationRoom: jest.fn(),
        broadcastNewMessage: jest.fn(),
        fanOutToParticipants: jest.fn(),
      };
      const unused: any = {};
      controller = new MessengerController(
        service, gateway, unused, unused, unused, unused, unused,
        unused, unused, unused, unused, unused, unused, scope,
      );
    });

    it('shows partners only direct chats and groups', async () => {
      await expect(controller.list(partnerUser)).resolves.toEqual([
        { id: 'c1', type: 'DIRECT' },
        { id: 'c3', type: 'GROUP' },
      ]);
      await expect(controller.list(nativeUser)).resolves.toHaveLength(4);
    });

    it('still filters read state by visible conversations for partners', async () => {
      await expect(controller.readState(partnerUser)).resolves.toEqual({ conversations: [{ conversationId: 'c1' }] });
      await expect(controller.readState(nativeUser)).resolves.toEqual({
        conversations: [{ conversationId: 'c1' }, { conversationId: 'c2' }],
      });
      expect(scope.visibleConversationIds).toHaveBeenCalledTimes(1);
    });

    it('asks the service to restrict sync to partner-visible conversation types, unfiltered by the controller', async () => {
      // Фильтрация теперь — в самом запросе сервиса (курсор иначе протекал по
      // скрытым беседам), контроллер просто передаёт список типов и отдаёт
      // страницу как есть.
      await expect(controller.sync(undefined, undefined, partnerUser)).resolves.toEqual({
        messages: [{ id: 'm1', conversationId: 'c1' }, { id: 'm2', conversationId: 'c2' }],
        nextCursor: 'x',
        hasMore: false,
      });
      expect(service.sync).toHaveBeenCalledWith('u1', undefined, 200, PARTNER_CONVERSATION_TYPES);

      await controller.sync(undefined, undefined, nativeUser);
      expect(service.sync).toHaveBeenLastCalledWith('u1', undefined, 200, undefined);
      expect(scope.visibleConversationIds).not.toHaveBeenCalled();
    });

    it('asks the service to restrict message search to partner-visible conversation types, unfiltered by the controller', async () => {
      await expect(controller.searchMessages('hi', partnerUser)).resolves.toEqual([
        { id: 'm1', conversationId: 'c1' },
        { id: 'm2', conversationId: 'c4' },
      ]);
      expect(service.searchMessages).toHaveBeenCalledWith('hi', 'u1', PARTNER_CONVERSATION_TYPES);

      await controller.searchMessages('hi', nativeUser);
      expect(service.searchMessages).toHaveBeenLastCalledWith('hi', 'u1', undefined);
      expect(scope.visibleConversationIds).not.toHaveBeenCalled();
    });

    describe('forward', () => {
      it('checks every source message for a partner before asking the service to forward', async () => {
        const order: string[] = [];
        scope.assertMessages.mockImplementation(async () => {
          order.push('assertMessages');
        });
        service.forwardMessages.mockImplementation(async () => {
          order.push('forwardMessages');
          return [];
        });

        await controller.forwardMessages('c1', ['m1', 'm2'], partnerUser);

        expect(scope.assertMessages).toHaveBeenCalledWith(['m1', 'm2']);
        expect(order).toEqual(['assertMessages', 'forwardMessages']);
      });

      it('a rejecting scope stops the forward before the service is called', async () => {
        scope.assertMessages.mockRejectedValue(new ForbiddenException('not_available_for_partner'));

        await expect(controller.forwardMessages('c1', ['m1'], partnerUser)).rejects.toThrow(ForbiddenException);
        expect(service.forwardMessages).not.toHaveBeenCalled();
      });

      it('does not check source messages for a native caller', async () => {
        await controller.forwardMessages('c1', ['m1'], nativeUser);
        expect(scope.assertMessages).not.toHaveBeenCalled();
        expect(service.forwardMessages).toHaveBeenCalledWith('c1', 'u1', ['m1']);
      });
    });

    it('lets partners put only their contacts into groups', async () => {
      await controller.createGroup({ name: 'G', participantIds: ['u2'] } as any, partnerUser);
      expect(scope.assertAllContacts).toHaveBeenCalledWith('u1', ['u2']);
      // group_created is announced through the type-aware helper so a partner
      // socket of the same user also gets it (puser:<id>), hard-coded to
      // GROUP since createGroupConversation never produces anything else.
      expect(gateway.emitToUserInConversation).toHaveBeenCalledWith('u1', 'GROUP', 'group_created', {
        conversationId: 'g1',
        name: 'G',
      });
      expect(gateway.emitToUserInConversation).toHaveBeenCalledWith('u2', 'GROUP', 'group_created', {
        conversationId: 'g1',
        name: 'G',
      });
      await controller.addMembers('g1', { userIds: ['u3'] } as any, partnerUser);
      expect(scope.assertAllContacts).toHaveBeenCalledWith('u1', ['u3']);
      scope.assertAllContacts.mockClear();
      await controller.createGroup({ name: 'G', participantIds: ['u9'] } as any, nativeUser);
      expect(scope.assertAllContacts).not.toHaveBeenCalled();
    });

    /**
     * group_member_added / group_role_changed / group_updated / leaveGroup's
     * group_member_removed all sit behind service methods that assert
     * conv.type === 'GROUP' and throw otherwise (addGroupMembers,
     * changeGroupMemberRole, updateGroupInfo, leaveGroup) — by the time the
     * controller reaches the emit, the type can only be GROUP. There is no
     * CHANNEL case to test here: these endpoints reject non-GROUP beседы
     * before any emit runs, unlike e.g. conversation_state which handles any
     * conversation type and genuinely looks the type up.
     */
    describe('remaining group events mirror to puser:<id> (GROUP, guaranteed by the service)', () => {
      it('group_member_added (addMembers)', async () => {
        service.addGroupMembers.mockResolvedValue(['u3']);
        await controller.addMembers('g1', { userIds: ['u3'] } as any, nativeUser);
        expect(gateway.emitToConversationParticipantsInConversation).toHaveBeenCalledWith(
          'g1',
          'GROUP',
          'group_member_added',
          { conversationId: 'g1', userIds: ['u3'] },
        );
      });

      it('group_role_changed (changeRole)', async () => {
        await controller.changeRole('g1', 'u3', { role: 'ADMIN' } as any, nativeUser);
        expect(gateway.emitToConversationParticipantsInConversation).toHaveBeenCalledWith(
          'g1',
          'GROUP',
          'group_role_changed',
          { conversationId: 'g1', userId: 'u3', newRole: 'ADMIN' },
        );
      });

      it('group_updated (updateGroup)', async () => {
        await controller.updateGroup('g1', { name: 'New name' } as any, nativeUser);
        expect(gateway.emitToConversationParticipantsInConversation).toHaveBeenCalledWith(
          'g1',
          'GROUP',
          'group_updated',
          expect.objectContaining({ conversationId: 'g1', name: 'New name' }),
        );
      });

      it('group_member_removed (leaveGroup, self-leave)', async () => {
        await controller.leaveGroup('g1', nativeUser);
        expect(gateway.emitToConversationParticipantsInConversation).toHaveBeenCalledWith(
          'g1',
          'GROUP',
          'group_member_removed',
          { conversationId: 'g1', userId: 'u1' },
        );
      });
    });
  });
});
