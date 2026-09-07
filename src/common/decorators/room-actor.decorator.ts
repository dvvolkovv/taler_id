import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Достаёт `req.roomActor` — его кладёт `RoomAccessGuard` при успешной
 * проверке доступа к комнате. Это идентификатор отправителя *в комнате*,
 * а не стабильная ссылка на аккаунт Taler ID: форма зависит от того, какое
 * доказательство сработало — `guest-<hex>`, имя агента вроде
 * `meeting-recorder`, голый uuid пользователя или `<uuid>#<хеш-устройства>`
 * для вошедшего каллера на LiveKit-токене (см. комментарий класса guard'а).
 * `undefined`, если guard, который его выставляет, на маршруте не стоит.
 */
export const RoomActor = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): string | undefined => {
    const request = ctx.switchToHttp().getRequest();
    return request.roomActor;
  },
);
