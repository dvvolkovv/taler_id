// ~/taler-id/src/messenger/dto/sync.dto.ts

export class SyncQueryDto {
  cursor?: string;
  limit?: string; // string because @Query() values arrive as strings
}

export interface SyncResultMessage {
  id: string;
  conversationId: string;
  senderId: string | null;
  content: string | null;
  sentAt: Date;
  // …all other Message fields, see existing MessengerService.getMessages
  // enrichment for the canonical shape (senderName, reactions[]).
  [key: string]: unknown;
}

export interface SyncResultDto {
  messages: SyncResultMessage[];
  nextCursor: string | null;
  hasMore: boolean;
}
