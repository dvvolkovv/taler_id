import { Injectable } from '@nestjs/common';

/**
 * Stub gateway for group voice call Socket.io fan-out. Real implementation
 * (Task 13) will inject MessengerGateway and emit to per-user rooms with the
 * documented event payloads. For Phase 1 Tasks 4-9 we just need the methods
 * to exist so GroupCallService can call them and unit tests can mock them.
 */
@Injectable()
export class GroupCallGateway {
  emitInvite(_userId: string, _payload: any): void {
    // TODO(Task 13): emit `group_call_invite` to user room.
  }

  emitStatus(_userIds: string[], _payload: any): void {
    // TODO(Task 13): emit `group_call_status` (state changes) to participants.
  }

  emitJoined(_userIds: string[], _payload: any): void {
    // TODO(Task 13): emit `group_call_joined` when a participant joins.
  }

  emitLeft(_userIds: string[], _payload: any): void {
    // TODO(Task 13): emit `group_call_left` when a participant leaves.
  }

  emitKicked(_userId: string, _payload: any): void {
    // TODO(Task 13): emit `group_call_kicked` to the kicked user.
  }

  emitMuteRequest(_userIds: string[], _payload: any): void {
    // TODO(Task 13): emit `group_call_mute_request` (host-issued).
  }

  emitHostChanged(_userIds: string[], _payload: any): void {
    // TODO(Task 13): emit `group_call_host_changed` after host transfer.
  }

  emitEnded(_userIds: string[], _payload: any): void {
    // TODO(Task 13): emit `group_call_ended` when call closes.
  }
}
