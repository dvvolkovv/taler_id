import { roomActorFactory } from './room-actor.decorator';

// `@RoomActor()` сам по себе — не вызываемая функция (createParamDecorator
// возвращает декоратор параметра, а не то, что можно дёрнуть напрямую), но
// логика, которую Nest вызовет за него на реальном запросе, вынесена в
// `roomActorFactory` ровно для того, чтобы её можно было проверить здесь,
// без поднятия Nest-пайплайна. Форма фейкового ExecutionContext — та же,
// что в room-access.guard.spec.ts (`ctxWithReq`), это единственное место
// в репозитории, где он уже собирается вручную.
const ctxWithReq = (req: any) =>
  ({ switchToHttp: () => ({ getRequest: () => req }) }) as any;

describe('roomActorFactory (@RoomActor())', () => {
  it('достаёт req.roomActor, который положил RoomAccessGuard', () => {
    expect(
      roomActorFactory(undefined, ctxWithReq({ roomActor: 'guest-abc123' })),
    ).toBe('guest-abc123');
  });

  it('достаёт actor с # — форму, которую кладёт LiveKit-ветка для вошедшего каллера', () => {
    expect(
      roomActorFactory(
        undefined,
        ctxWithReq({ roomActor: 'user-9f8e#device-ab12' }),
      ),
    ).toBe('user-9f8e#device-ab12');
  });

  it('возвращает undefined, если на запросе нет roomActor', () => {
    expect(roomActorFactory(undefined, ctxWithReq({}))).toBeUndefined();
  });
});
