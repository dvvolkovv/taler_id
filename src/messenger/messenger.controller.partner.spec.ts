import { MessengerAuthGuard } from './messenger-auth.guard';
import { MessengerController } from './messenger.controller';
import { PARTNER_ALLOWED_KEY, PartnerAllowedOptions } from './partner-allowed.decorator';

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
  pinMessage: { conversationParam: 'id' },
  unpinMessage: { conversationParam: 'id' },
  listPinned: { conversationParam: 'id' },
  unpinAll: { conversationParam: 'id' },
  dismissPins: { conversationParam: 'id' },
  getThread: { conversationParam: 'convId' },
  sendThreadReply: { conversationParam: 'convId' },
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
      };
      scope = {
        visibleConversationIds: jest.fn().mockResolvedValue(new Set(['c1', 'c3'])),
        assertAllContacts: jest.fn().mockResolvedValue(undefined),
      };
      const gateway: any = { emitToUser: jest.fn(), emitToConversationParticipants: jest.fn() };
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

    it('filters sync, read state and message search by visible conversations', async () => {
      await expect(controller.sync(undefined, undefined, partnerUser)).resolves.toEqual({
        messages: [{ id: 'm1', conversationId: 'c1' }],
        nextCursor: 'x',
        hasMore: false,
      });
      await expect(controller.readState(partnerUser)).resolves.toEqual({ conversations: [{ conversationId: 'c1' }] });
      await expect(controller.searchMessages('hi', partnerUser)).resolves.toEqual([{ id: 'm1', conversationId: 'c1' }]);
      const nativeSync: any = await controller.sync(undefined, undefined, nativeUser);
      expect(nativeSync.messages).toHaveLength(2);
      expect(scope.visibleConversationIds).toHaveBeenCalledTimes(3);
    });

    it('lets partners put only their contacts into groups', async () => {
      await controller.createGroup({ name: 'G', participantIds: ['u2'] } as any, partnerUser);
      expect(scope.assertAllContacts).toHaveBeenCalledWith('u1', ['u2']);
      await controller.addMembers('g1', { userIds: ['u3'] } as any, partnerUser);
      expect(scope.assertAllContacts).toHaveBeenCalledWith('u1', ['u3']);
      scope.assertAllContacts.mockClear();
      await controller.createGroup({ name: 'G', participantIds: ['u9'] } as any, nativeUser);
      expect(scope.assertAllContacts).not.toHaveBeenCalled();
    });
  });
});
