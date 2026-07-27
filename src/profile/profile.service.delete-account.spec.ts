import { Test, TestingModule } from '@nestjs/testing';
import { ProfileService } from './profile.service';
import { PrismaService } from '../prisma/prisma.service';
import { FileStorageService } from '../common/file-storage.service';

// Regression cover for the account-deletion path: Prisma silently drops
// `undefined` filters, so an unscoped `document.deleteMany` would delete every
// row in the table instead of just the caller's documents.
const mockPrisma = {
  profile: {
    findUnique: jest.fn(),
    deleteMany: jest.fn(),
  },
  document: {
    deleteMany: jest.fn(),
  },
  kycRecord: {
    deleteMany: jest.fn(),
  },
  session: {
    deleteMany: jest.fn(),
  },
  totpSecret: {
    deleteMany: jest.fn(),
  },
  user: {
    update: jest.fn(),
  },
  $transaction: jest.fn(),
};

const mockFileStorage = {
  upload: jest.fn(),
  getPublicUrl: jest.fn(),
  delete: jest.fn(),
  getObject: jest.fn(),
};

describe('ProfileService.deleteAccount', () => {
  let service: ProfileService;

  beforeEach(async () => {
    jest.clearAllMocks();
    mockPrisma.$transaction.mockResolvedValue(undefined);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ProfileService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: FileStorageService, useValue: mockFileStorage },
      ],
    }).compile();

    service = module.get<ProfileService>(ProfileService);
  });

  it('scopes document deletion to the caller profile', async () => {
    mockPrisma.profile.findUnique.mockResolvedValue({
      id: 'profile-1',
      userId: 'user-1',
    });

    await service.deleteAccount('user-1');

    expect(mockPrisma.document.deleteMany).toHaveBeenCalledWith({
      where: { profileId: 'profile-1' },
    });
  });

  it('never issues an unscoped document delete when the user has no profile', async () => {
    mockPrisma.profile.findUnique.mockResolvedValue(null);

    await service.deleteAccount('user-1');

    // Must not run at all — `{ profileId: undefined }` would wipe every user's documents.
    expect(mockPrisma.document.deleteMany).not.toHaveBeenCalled();
  });

  it('still anonymises the user when no profile exists', async () => {
    mockPrisma.profile.findUnique.mockResolvedValue(null);

    const result = await service.deleteAccount('user-1');

    expect(mockPrisma.user.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 'user-1' },
        data: expect.objectContaining({
          email: null,
          phone: null,
          passwordHash: null,
        }),
      }),
    );
    expect(result.success).toBe(true);
  });
});
