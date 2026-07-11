import { FcmService } from './fcm.service';
describe('FcmService notification id', () => {
  const svc = new FcmService({} as any);
  it('is stable + conversation-scoped', () => {
    const a = svc.notificationIdFor('conv-123');
    expect(a).toBe(svc.notificationIdFor('conv-123'));
    expect(a).not.toBe(svc.notificationIdFor('conv-456'));
    expect(a.startsWith('conv-')).toBe(true);
  });
});
