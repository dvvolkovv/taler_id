import { ForbiddenException } from '@nestjs/common';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { VoiceController } from '../voice.controller';
import {
  isInterpreterRoom,
  NotInterpreterRoomGuard,
} from './not-interpreter-room.guard';

const ctxFor = (roomName?: string) =>
  ({
    switchToHttp: () => ({ getRequest: () => ({ params: { roomName } }) }),
  }) as any;

describe('NotInterpreterRoomGuard', () => {
  const guard = new NotInterpreterRoomGuard();

  it('refuses an interpreter room with 403 interpreter_room', () => {
    let err: unknown;
    try {
      guard.canActivate(ctxFor('interp-0f8fad5b-d9cb-469f-a165-70867728950e'));
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ForbiddenException);
    expect((err as ForbiddenException).message).toBe('interpreter_room');
  });

  it('lets every other room through', () => {
    for (const room of ['call-1', 'group-1', 'personal-ab12cd34-1', 'tmp-1']) {
      expect(guard.canActivate(ctxFor(room))).toBe(true);
    }
    expect(isInterpreterRoom(undefined)).toBe(false);
  });

  it('stands behind the token on every room route that has no room check', () => {
    // These routes take any Taler ID token: without the guard a participant,
    // who knows the room's name, could start them in an interpreter room.
    for (const route of [
      'disableE2EE',
      'startTranslator',
      'stopTranslator',
      'setTranslatorLang',
      'startHoldMusic',
      'stopHoldMusic',
    ] as const) {
      expect(
        Reflect.getMetadata(GUARDS_METADATA, VoiceController.prototype[route]),
      ).toEqual([JwtAuthGuard, NotInterpreterRoomGuard]);
    }
  });
});
