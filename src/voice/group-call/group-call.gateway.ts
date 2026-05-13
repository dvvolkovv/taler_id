import { Injectable } from '@nestjs/common';
import { MessengerGateway } from '../../messenger/messenger.gateway';

/**
 * Socket.io event publisher for group voice calls (Phase 1).
 *
 * Routes group-call events to the existing `MessengerGateway` Socket.io
 * server, keeping a single namespace and connection per client. Events emitted
 * here are scoped to specific user rooms (`user:{userId}`).
 *
 * EVENT-NAME COLLISION WARNING:
 * `MessengerGateway` already emits `group_call_started` and `group_call_ended`
 * for the legacy conversation-based voice flow:
 *   - Legacy `group_call_ended` payload: { conversationId, roomName }
 *   - This module's `group_call_ended` payload: { groupCallId, reason }
 * Mobile clients must disambiguate by checking which field is present in
 * the payload (presence of `groupCallId` => Phase 1 GroupCall flow). The
 * legacy flow is slated for retirement in Phase 2+; until then, the wire
 * formats coexist and the spec deliberately reuses `group_call_*` names
 * for forward compatibility with the mobile BLoC events.
 */
@Injectable()
export class GroupCallGateway {
  constructor(private readonly messenger: MessengerGateway) {}

  emitInvite(userId: string, payload: { groupCallId: string; host: any; invitees: any[] }) {
    this.messenger.emitToUser(userId, 'group_call_invite', payload);
  }

  emitStatus(userIds: string[], payload: { groupCallId: string; invites: any[] }) {
    for (const uid of userIds) {
      this.messenger.emitToUser(uid, 'group_call_status', payload);
    }
  }

  emitJoined(userIds: string[], payload: { groupCallId: string; userId: string; joinedAt: Date }) {
    for (const uid of userIds) {
      this.messenger.emitToUser(uid, 'group_call_joined', payload);
    }
  }

  emitLeft(userIds: string[], payload: { groupCallId: string; userId: string; leftAt: Date }) {
    for (const uid of userIds) {
      this.messenger.emitToUser(uid, 'group_call_left', payload);
    }
  }

  emitKicked(userId: string, payload: { groupCallId: string; by: string }) {
    this.messenger.emitToUser(userId, 'group_call_kicked', payload);
  }

  emitMuteRequest(userIds: string[], payload: { groupCallId: string; by: string }) {
    for (const uid of userIds) {
      this.messenger.emitToUser(uid, 'group_call_mute_request', payload);
    }
  }

  emitHostChanged(userIds: string[], payload: { groupCallId: string; newHostUserId: string }) {
    for (const uid of userIds) {
      this.messenger.emitToUser(uid, 'group_call_host_changed', payload);
    }
  }

  emitEnded(userIds: string[], payload: { groupCallId: string; reason: string }) {
    for (const uid of userIds) {
      this.messenger.emitToUser(uid, 'group_call_ended', payload);
    }
  }
}
