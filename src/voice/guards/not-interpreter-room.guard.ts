import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';

/** Rooms of a conversation with translation, named by src/interpreter. */
export function isInterpreterRoom(roomName: unknown): boolean {
  return typeof roomName === 'string' && roomName.startsWith('interp-');
}

/**
 * For the room routes that trust a Taler ID token alone: the call translator,
 * the E2EE switch, hold music. Both people in an interpreter room know its
 * name, and none of these belongs there: the call translator would talk over
 * the agent, hold music would play into both phones.
 */
@Injectable()
export class NotInterpreterRoomGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    if (isInterpreterRoom(ctx.switchToHttp().getRequest().params?.roomName)) {
      throw new ForbiddenException('interpreter_room');
    }
    return true;
  }
}
