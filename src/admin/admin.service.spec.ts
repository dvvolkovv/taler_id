import { AdminService } from './admin.service';

/**
 * Блокировка пользователя администратором (deleteUser — несмотря на имя,
 * штатная процедура только ставит deletedAt, почту не обнуляет) должна сразу
 * отзывать партнёрские связки блокируемого — иначе партнёр (nadi) продолжает
 * читать и писать от имени заблокированного аккаунта до истечения выданных
 * токенов. Спека: docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md
 */
describe('AdminService.deleteUser — revokes partner links on block', () => {
  function make(revokeAllForUser: jest.Mock = jest.fn().mockResolvedValue(0)) {
    const prisma: any = {
      user: { update: jest.fn().mockResolvedValue({ id: 'u1' }) },
    };
    const partnerLinks: any = { revokeAllForUser };
    const service = new AdminService(
      prisma,
      {} as any,
      {} as any,
      {} as any,
      partnerLinks,
    );
    return { service, prisma, partnerLinks };
  }

  it('blocks the account and revokes all of its partner links', async () => {
    const { service, prisma, partnerLinks } = make();
    await expect(service.deleteUser('u1')).resolves.toEqual({
      success: true,
    });
    expect(prisma.user.update).toHaveBeenCalledWith({
      where: { id: 'u1' },
      data: { deletedAt: expect.any(Date) },
    });
    expect(partnerLinks.revokeAllForUser).toHaveBeenCalledWith('u1');
  });

  it('still blocks the account and returns success when revocation fails (logged, not thrown)', async () => {
    const { service, prisma } = make(
      jest.fn().mockRejectedValue(new Error('redis down')),
    );
    const errorSpy = jest.spyOn((service as any).logger, 'error');
    await expect(service.deleteUser('u1')).resolves.toEqual({
      success: true,
    });
    expect(prisma.user.update).toHaveBeenCalled();
    expect(errorSpy).toHaveBeenCalled();
  });

  it('blocks the account before attempting revocation', async () => {
    const { service, prisma, partnerLinks } = make();
    await service.deleteUser('u1');
    expect(prisma.user.update.mock.invocationCallOrder[0]).toBeLessThan(
      partnerLinks.revokeAllForUser.mock.invocationCallOrder[0],
    );
  });
});
