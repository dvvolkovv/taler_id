import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { DeviceKeysService } from './device-keys.service';

// Regression cover for the 2026-07-27 audit finding: listForContact ignored the
// caller (the parameter was literally named `_callerId`), so any authenticated
// user could enumerate anyone's registered devices.
describe('DeviceKeysService.listForContact contact check', () => {
  let service: DeviceKeysService;
  let prisma: any;

  const CALLER = 'caller-1';
  const TARGET = 'target-1';

  beforeEach(() => {
    prisma = {
      user: { findUnique: jest.fn().mockResolvedValue({ id: TARGET }) },
      contactRequest: { findFirst: jest.fn().mockResolvedValue(null) },
      conversation: { findFirst: jest.fn().mockResolvedValue(null) },
      deviceKey: { findMany: jest.fn().mockResolvedValue([]) },
    };
    service = new DeviceKeysService(prisma, { sendKeyUpdate: jest.fn() } as any);
  });

  it('refuses a caller who is neither a contact nor a chat partner', async () => {
    await expect(service.listForContact(CALLER, TARGET)).rejects.toThrow(
      ForbiddenException,
    );

    expect(prisma.deviceKey.findMany).not.toHaveBeenCalled();
  });

  it('allows an accepted contact', async () => {
    prisma.contactRequest.findFirst.mockResolvedValue({ id: 'cr-1' });

    await expect(
      service.listForContact(CALLER, TARGET),
    ).resolves.toEqual([]);
    expect(prisma.deviceKey.findMany).toHaveBeenCalled();
  });

  it('allows a legacy pair that shares a direct conversation', async () => {
    // Conversations created before the contact-request feature have no
    // ContactRequest row; the messenger makes the same allowance.
    prisma.conversation.findFirst.mockResolvedValue({ id: 'conv-1' });

    await expect(
      service.listForContact(CALLER, TARGET),
    ).resolves.toEqual([]);
    expect(prisma.deviceKey.findMany).toHaveBeenCalled();
  });

  it('lets a user list their own devices without a contact record', async () => {
    prisma.user.findUnique.mockResolvedValue({ id: CALLER });

    await expect(
      service.listForContact(CALLER, CALLER),
    ).resolves.toEqual([]);
    expect(prisma.contactRequest.findFirst).not.toHaveBeenCalled();
  });

  it('still reports an unknown user as not found', async () => {
    prisma.user.findUnique.mockResolvedValue(null);

    await expect(service.listForContact(CALLER, 'ghost')).rejects.toThrow(
      NotFoundException,
    );
  });
});
