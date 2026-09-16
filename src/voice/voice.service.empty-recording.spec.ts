// A recording that captured nothing has to reach the person who started it.
//
// The recorder leaves a `failed_no_audio` row for exactly that reason. But it
// only knows the participants it heard — and in this case it heard nobody, so
// the row goes in with an empty `participantIds`. `GET /voice/meetings` matches
// on participation or on a `personal-<owner>` room name, so for a temporary
// public room the row belongs to no one and is invisible to everybody: the
// fail-loud path stays silent after all.
//
// Whoever opened the room is recorded on PublicRoom.creatorId, which works
// regardless of which app node the recorder's save lands on.
process.env.LIVEKIT_WS_URL = 'wss://test.example.com/livekit';

import { Test, TestingModule } from '@nestjs/testing';
import { VoiceService } from './voice.service';
import { PrismaService } from '../prisma/prisma.service';
import { FileStorageService } from '../common/file-storage.service';
import { GatingService } from '../billing/services/gating.service';
import { MeteringService } from '../billing/services/metering.service';
import { LedgerService } from '../billing/services/ledger.service';
import { PricingService } from '../billing/services/pricing.service';
import { RoomChatBufferService } from './room-chat-buffer.service';

const CREATOR_ID = 'c79530ed-5ba8-44e3-b7d4-4a591c7c1db6';
const ROOM = 'tmp-2d77b1f6-c886-443c-8e8a-5fa825483a8a';

const mockPrisma = {
  meetingSummary: { create: jest.fn(), update: jest.fn() },
  callLog: { findUnique: jest.fn() },
  publicRoom: { findFirst: jest.fn() },
};
const stub = () => ({}) as any;

const emptyRecording = {
  roomName: ROOM,
  transcript: '',
  summary: 'Запись не записалась: recorder не получил аудио из комнаты.',
  keyPoints: [],
  actionItems: [],
  decisions: [],
  participants: [] as string[],
  participantIds: [] as string[],
  durationSec: 6,
  status: 'failed_no_audio',
};

describe('saveMeetingSummary — a recording that captured nobody', () => {
  let service: VoiceService;

  beforeEach(async () => {
    jest.clearAllMocks();
    mockPrisma.meetingSummary.create.mockResolvedValue({ id: 'm-1' });
    mockPrisma.callLog.findUnique.mockResolvedValue(null);
    mockPrisma.publicRoom.findFirst.mockResolvedValue({
      roomName: ROOM,
      creatorId: CREATOR_ID,
    });

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        VoiceService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: FileStorageService, useValue: stub() },
        { provide: GatingService, useValue: stub() },
        { provide: MeteringService, useValue: stub() },
        { provide: LedgerService, useValue: stub() },
        { provide: PricingService, useValue: stub() },
        { provide: RoomChatBufferService, useValue: stub() },
      ],
    }).compile();

    service = module.get<VoiceService>(VoiceService);
  });

  const createdData = () => mockPrisma.meetingSummary.create.mock.calls[0][0].data;

  it('files it under whoever opened the room, so they can see it failed', async () => {
    await service.saveMeetingSummary({ ...emptyRecording });

    expect(createdData().participantIds).toEqual([CREATOR_ID]);
  });

  it('leaves the participants the recorder did hear alone', async () => {
    await service.saveMeetingSummary({
      ...emptyRecording,
      participants: ['Dmitry Volkov'],
      participantIds: ['guest-1'],
      status: 'done',
    });

    expect(createdData().participantIds).toEqual(['guest-1']);
    expect(mockPrisma.publicRoom.findFirst).not.toHaveBeenCalled();
  });

  // participantIds is an access-control list, matched against a bare userId by
  // the listings and by the transcription guard. The recorder reports LiveKit
  // identities, which carry a per-device hash for app participants — keeping it
  // locks the participant out of their own recording.
  it('strips the device hash off the identities the recorder reports', async () => {
    await service.saveMeetingSummary({
      ...emptyRecording,
      participants: ['Дмитрий Волков', 'Aleksandr Shevchenko'],
      participantIds: [
        'fc7d449b-84ac-4048-b3c5-7e6d49a091e7#1d5589ab',
        '51a2323d-7080-4ba5-a084-688815053699#89455dbf',
      ],
      status: 'done',
    });

    expect(createdData().participantIds).toEqual([
      'fc7d449b-84ac-4048-b3c5-7e6d49a091e7',
      '51a2323d-7080-4ba5-a084-688815053699',
    ]);
  });

  // The same person on a phone and a laptop is two LiveKit identities but one
  // entry in an ACL.
  it('collapses the same person joining from two devices', async () => {
    await service.saveMeetingSummary({
      ...emptyRecording,
      participants: ['Дмитрий Волков', 'Дмитрий Волков'],
      participantIds: [
        'fc7d449b-84ac-4048-b3c5-7e6d49a091e7#1d5589ab',
        'fc7d449b-84ac-4048-b3c5-7e6d49a091e7#9f0c2ab4',
      ],
      status: 'done',
    });

    expect(createdData().participantIds).toEqual([
      'fc7d449b-84ac-4048-b3c5-7e6d49a091e7',
    ]);
  });

  it('still saves when the room has no creator on record', async () => {
    // Rooms created before creatorId was populated, and personal rooms, which
    // have no PublicRoom row at all — the owner clause in the list covers those.
    mockPrisma.publicRoom.findFirst.mockResolvedValue(null);

    await service.saveMeetingSummary({ ...emptyRecording });

    expect(createdData().participantIds).toEqual([]);
    expect(createdData().status).toBe('failed_no_audio');
  });

  it('survives the room lookup failing', async () => {
    // Losing the row is worse than losing the attribution.
    mockPrisma.publicRoom.findFirst.mockRejectedValue(new Error('db down'));

    await expect(
      service.saveMeetingSummary({ ...emptyRecording }),
    ).resolves.toEqual({ id: 'm-1' });
  });
});
