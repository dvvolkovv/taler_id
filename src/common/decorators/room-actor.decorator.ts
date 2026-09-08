import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Достаёт `req.roomActor` — его кладёт `RoomAccessGuard` при успешной
 * проверке доступа к комнате. Это идентификатор отправителя *в комнате*,
 * а не стабильная ссылка на аккаунт Taler ID: форма зависит от того, какое
 * доказательство сработало — `guest-<hex>`, имя агента вроде
 * `meeting-recorder`, голый uuid пользователя или `<uuid>#<хеш-устройства>`
 * для вошедшего каллера на LiveKit-токене (см. комментарий класса guard'а).
 * `undefined`, если guard, который его выставляет, на маршруте не стоит.
 *
 * Логика вынесена в именованную функцию, а не анонимную стрелку внутри
 * `createParamDecorator`, чтобы её можно было проверить тестом напрямую —
 * `createParamDecorator` даёт декоратор параметра, а не вызываемую функцию,
 * и внутри него опечатку в `roomActor` ничем, кроме юнит-теста именно этой
 * функции, не поймать: контроллер получит молчаливый `undefined` вместо
 * актора, потолок на запись в чате тихо перестанет работать, а все
 * остальные тесты (они передают actor уже как обычный аргумент) останутся
 * зелёными.
 */
export function roomActorFactory(
  data: unknown,
  ctx: ExecutionContext,
): string | undefined {
  const request = ctx.switchToHttp().getRequest();
  return request.roomActor;
}

export const RoomActor = createParamDecorator(roomActorFactory);
