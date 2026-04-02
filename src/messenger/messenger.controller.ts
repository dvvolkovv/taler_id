import {
  Controller, Get, Post, Put, Patch, Delete, Body, Param, Query, UseGuards,
  UseInterceptors, UploadedFile, ForbiddenException, Logger,
  Res, StreamableFile, NotFoundException,
} from '@nestjs/common';
import type { Response } from 'express';
import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { extname } from 'path';
import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';
import { MessengerService } from './messenger.service';
import { MessengerGateway } from './messenger.gateway';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { CreateGroupDto } from './dto/create-group.dto';
import { UpdateGroupDto } from './dto/update-group.dto';
import { AddMembersDto } from './dto/add-members.dto';
import { ChangeGroupRoleDto } from './dto/change-role.dto';
import { FileStorageService } from '../common/file-storage.service';
import { ThumbnailService } from '../common/thumbnail.service';
import { Public } from '../common/decorators/public.decorator';
import { RedisService } from '../redis/redis.service';
import { PrismaService } from '../prisma/prisma.service';
import { VideoTranscodeService } from '../common/video-transcode.service';
import { FcmService } from '../common/fcm.service';
import sharp = require('sharp');

@Controller('messenger')
@UseGuards(JwtAuthGuard)
export class MessengerController {
  private readonly logger = new Logger(MessengerController.name);

  constructor(
    private readonly service: MessengerService,
    private readonly gateway: MessengerGateway,
    private readonly fileStorage: FileStorageService,
    private readonly thumbnailService: ThumbnailService,
    private readonly redis: RedisService,
    private readonly prisma: PrismaService,
    private readonly videoTranscode: VideoTranscodeService,
    private readonly fcmService: FcmService,
  ) {}

  /**
   * Compute a content hash for deduplication.
   * For images: hash raw pixel data (ignoring EXIF metadata that iOS changes on each export).
   * For everything else: hash the full file bytes.
   */
  private async computeContentHash(data: Buffer, mimeType: string): Promise<string> {
    if (mimeType.startsWith('image/')) {
      try {
        const rawPixels = await sharp(data).raw().toBuffer();
        return createHash('sha256').update(rawPixels).digest('hex');
      } catch {
        // Fallback to full file hash if sharp fails
      }
    }
    return createHash('sha256').update(data).digest('hex');
  }

  // ─── Direct conversations ───

  @Post('conversations')
  async create(@Body('participantId') participantId: string, @CurrentUser() user: any) {
    // Check if either user has blocked the other
    const isBlocked = await this.service.isBlockedBy(user.sub, participantId);
    if (isBlocked) throw new ForbiddenException('Нет доступа');
    // Check if there's an existing conversation (bypass contact check)
    // or if they have an accepted contact
    const hasContact = await this.service.hasContactWith(user.sub, participantId);
    if (!hasContact) {
      // Check if conversation already exists (legacy contacts from before contact request feature)
      const existing = await this.service.findExistingDirectConversation(user.sub, participantId);
      if (!existing) {
        throw new ForbiddenException('Нужно сначала отправить запрос на общение');
      }
    }
    return this.service.getOrCreateDirectConversation(user.sub, participantId);
  }

  @Get('conversations')
  list(@CurrentUser() user: any) {
    return this.service.getConversations(user.sub);
  }

  @Get('conversations/:id/messages')
  messages(
    @Param('id') id: string,
    @Query('cursor') cursor: string,
    @Query('limit') limit: string,
    @CurrentUser() user: any,
  ) {
    return this.service.getMessages(id, user.sub, cursor, limit ? +limit : 30);
  }

  @Get('conversations/:id/media')
  sharedMedia(
    @Param('id') id: string,
    @Query('type') type: string,
    @Query('cursor') cursor: string,
    @Query('limit') limit: string,
    @CurrentUser() user: any,
  ) {
    return this.service.getSharedMedia(id, user.sub, type, cursor, limit ? +limit : 50);
  }

  // ─── Group conversations ───

  @Post('conversations/group')
  async createGroup(@Body() dto: CreateGroupDto, @CurrentUser() user: any) {
    const conv = await this.service.createGroupConversation(user.sub, dto.name, dto.participantIds);
    // Notify all participants about the new group
    for (const pid of conv.participantIds) {
      this.gateway.emitToUser(pid, 'group_created', { conversationId: conv.id, name: dto.name });
    }
    return conv;
  }

  @Get('conversations/:id/members')
  getMembers(@Param('id') id: string, @CurrentUser() user: any) {
    return this.service.getGroupMembers(id, user.sub);
  }

  @Post('conversations/:id/members')
  async addMembers(
    @Param('id') id: string,
    @Body() dto: AddMembersDto,
    @CurrentUser() user: any,
  ) {
    const newIds = await this.service.addGroupMembers(id, user.sub, dto.userIds);
    if (newIds.length > 0) {
      await this.gateway.emitToConversationParticipants(id, 'group_member_added', {
        conversationId: id,
        userIds: newIds,
      });
      // Also notify newly added users so they refresh their conversation list
      for (const uid of newIds) {
        this.gateway.emitToUser(uid, 'group_created', { conversationId: id });
      }
    }
    return newIds;
  }

  @Delete('conversations/:id/members/:uid')
  async removeMember(
    @Param('id') id: string,
    @Param('uid') uid: string,
    @CurrentUser() user: any,
  ) {
    await this.service.removeGroupMember(id, user.sub, uid);
    await this.gateway.emitToConversationParticipants(id, 'group_member_removed', {
      conversationId: id,
      userId: uid,
    });
    // Also notify removed user
    this.gateway.emitToUser(uid, 'group_member_removed', {
      conversationId: id,
      userId: uid,
    });
  }

  @Patch('conversations/:id/members/:uid/role')
  async changeRole(
    @Param('id') id: string,
    @Param('uid') uid: string,
    @Body() dto: ChangeGroupRoleDto,
    @CurrentUser() user: any,
  ) {
    const result = await this.service.changeGroupMemberRole(id, user.sub, uid, dto.role);
    await this.gateway.emitToConversationParticipants(id, 'group_role_changed', {
      conversationId: id,
      userId: uid,
      newRole: dto.role,
    });
    return result;
  }

  @Patch('conversations/:id')
  async updateGroup(
    @Param('id') id: string,
    @Body() dto: UpdateGroupDto,
    @CurrentUser() user: any,
  ) {
    const result = await this.service.updateGroupInfo(id, user.sub, dto);
    await this.gateway.emitToConversationParticipants(id, 'group_updated', {
      conversationId: id,
      name: dto.name,
      avatarUrl: dto.avatarUrl,
      description: dto.description,
    });
    return result;
  }

  @Post('conversations/:id/mute')
  async muteConversation(
    @Param('id') id: string,
    @CurrentUser() user: any,
    @Body() body: { duration?: number },
  ) {
    return this.service.muteConversation(id, user.sub, body.duration);
  }

  @Post('conversations/:id/unmute')
  async unmuteConversation(@Param('id') id: string, @CurrentUser() user: any) {
    return this.service.unmuteConversation(id, user.sub);
  }

  @Post('conversations/:id/leave')
  async leaveGroup(@Param('id') id: string, @CurrentUser() user: any) {
    await this.service.leaveGroup(id, user.sub);
    await this.gateway.emitToConversationParticipants(id, 'group_member_removed', {
      conversationId: id,
      userId: user.sub,
    });
  }

  @Delete('conversations/:id')
  async deleteGroup(@Param('id') id: string, @CurrentUser() user: any) {
    // Get participants before deletion
    const members = await this.service.getGroupMembers(id, user.sub);
    await this.service.deleteGroup(id, user.sub);
    for (const m of members) {
      this.gateway.emitToUser(m.userId, 'group_deleted', { conversationId: id });
    }
  }

  // ─── Contact requests ───

  @Post('contacts/request')
  async sendContactRequest(@Body('receiverId') receiverId: string, @CurrentUser() user: any) {
    const result = await this.service.sendContactRequest(user.sub, receiverId);
    // If auto-accepted (reverse request existed), notify about acceptance
    if ('conversationId' in result) {
      this.gateway.emitToUser(receiverId, 'contact_request_accepted', {
        senderId: user.sub,
        conversationId: result.conversationId,
      });
      return result;
    }
    // Notify receiver about new request
    this.gateway.emitToUser(receiverId, 'contact_request', {
      id: result.id,
      senderId: user.sub,
      senderName: result.senderName,
      senderAvatar: result.senderAvatar,
      senderUsername: result.senderUsername,
    });
    // Send FCM push to receiver
    const receiverFcmToken = await this.service.getFcmToken(receiverId);
    if (receiverFcmToken) {
      this.fcmService.sendContactRequest(receiverFcmToken, result.senderName).catch(() => {});
    }
    return result;
  }

  @Get('contacts/requests')
  getContactRequests(@CurrentUser() user: any) {
    return this.service.getContactRequests(user.sub);
  }

  @Get('contacts/requests/sent')
  getSentContactRequests(@CurrentUser() user: any) {
    return this.service.getSentContactRequests(user.sub);
  }

  @Get('contacts/check/:userId')
  getContactStatus(@Param('userId') userId: string, @CurrentUser() user: any) {
    return this.service.getContactStatus(user.sub, userId);
  }


  @Patch('contacts/requests/:id/accept')
  async acceptContactRequest(@Param('id') id: string, @CurrentUser() user: any) {
    const result = await this.service.acceptContactRequest(id, user.sub);
    // Notify sender that request was accepted
    this.gateway.emitToUser(result.senderId, 'contact_request_accepted', {
      requestId: id,
      acceptedBy: user.sub,
      conversationId: result.conversationId,
    });
    // Send FCM push to sender about acceptance
    const senderFcmToken = await this.service.getFcmToken(result.senderId);
    if (senderFcmToken) {
      const acceptorName = await this.service.getUserDisplayName(user.sub);
      this.fcmService.sendNewMessage(senderFcmToken, 'Запрос принят', acceptorName + ' принял(а) ваш запрос на общение', result.conversationId).catch(() => {});
    }
    return result;
  }

  @Patch('contacts/requests/:id/reject')
  async rejectContactRequest(@Param('id') id: string, @CurrentUser() user: any) {
    const result = await this.service.rejectContactRequest(id, user.sub);
    // Send FCM push to sender about rejection
    if (result?.senderId) {
      const senderFcmToken = await this.service.getFcmToken(result.senderId);
      if (senderFcmToken) {
        const rejecterName = await this.service.getUserDisplayName(user.sub);
        this.fcmService.sendNewMessage(senderFcmToken, 'Запрос отклонён', rejecterName + ' отклонил(а) ваш запрос на общение', '').catch(() => {});
      }
    }
    return result;
  }

  // ─── Contact Aliases ───

  @Get("contacts/aliases")
  getAliases(@CurrentUser() user: any) {
    return this.service.getContactAliases(user.sub);
  }

  @Put("contacts/aliases/:targetId")
  setAlias(@CurrentUser() user: any, @Param("targetId") targetId: string, @Body("customName") customName: string) {
    return this.service.setContactAlias(user.sub, targetId, customName);
  }

  @Delete("contacts/aliases/:targetId")
  removeAlias(@CurrentUser() user: any, @Param("targetId") targetId: string) {
    return this.service.removeContactAlias(user.sub, targetId);
  }


  // ─── Contact delete & block ───

  @Delete('contacts/:userId')
  deleteContact(@CurrentUser() user: any, @Param('userId') userId: string) {
    return this.service.deleteContact(user.sub, userId);
  }

  @Post('contacts/:userId/block')
  blockUser(@CurrentUser() user: any, @Param('userId') userId: string) {
    return this.service.blockUser(user.sub, userId);
  }

  @Delete('contacts/:userId/block')
  unblockUser(@CurrentUser() user: any, @Param('userId') userId: string) {
    return this.service.unblockUser(user.sub, userId);
  }

  @Get('contacts/:userId/block')
  isBlocked(@CurrentUser() user: any, @Param('userId') userId: string) {
    return this.service.isBlockedBy(user.sub, userId).then(blocked => ({ blocked }));
  }

  // ─── Message search ───

  @Get("messages/search")
  searchMessages(@Query("q") q: string, @CurrentUser() user: any) {
    return this.service.searchMessages(q, user.sub);
  }

  // ─── User search ───

  @Get('users/search')
  search(@Query('q') q: string, @CurrentUser() user: any) {
    if (!q || q.length < 2) return [];
    return this.service.searchUsers(q, user.sub);
  }

  // ─── File upload (S3) ───

  @Post('files')
  @UseInterceptors(
    FileInterceptor('file', {
      storage: memoryStorage(),
      limits: { fileSize: 100 * 1024 * 1024 },
    }),
  )
  async uploadFile(@UploadedFile() file: Express.Multer.File) {
    const ext = extname(file.originalname);
    const s3Key = `files/${uuidv4()}${ext}`;

    // Determine file type
    let fileType = 'document';
    if (file.mimetype.startsWith('image/')) fileType = 'image';
    else if (file.mimetype.startsWith('video/')) fileType = 'video';
    else if (file.mimetype.startsWith('audio/')) fileType = 'audio';

    // Upload original to S3
    await this.fileStorage.upload(s3Key, file.buffer, file.mimetype);
    const fileUrl = this.fileStorage.getPublicUrl(s3Key);

    // Generate thumbnails
    let thumbnailSmallUrl: string | undefined;
    let thumbnailMediumUrl: string | undefined;
    let thumbnailLargeUrl: string | undefined;
    let thumbnailSmallKey: string | undefined;
    let thumbnailMediumKey: string | undefined;
    let thumbnailLargeKey: string | undefined;

    try {
      if (fileType === 'image') {
        const thumbs = await this.thumbnailService.generateImageThumbnails(file.buffer);
        if (thumbs.small) {
          thumbnailSmallKey = `thumbs/${uuidv4()}_s.webp`;
          await this.fileStorage.upload(thumbnailSmallKey, thumbs.small, 'image/webp');
          thumbnailSmallUrl = this.fileStorage.getPublicUrl(thumbnailSmallKey);
        }
        if (thumbs.medium) {
          thumbnailMediumKey = `thumbs/${uuidv4()}_m.webp`;
          await this.fileStorage.upload(thumbnailMediumKey, thumbs.medium, 'image/webp');
          thumbnailMediumUrl = this.fileStorage.getPublicUrl(thumbnailMediumKey);
        }
        if (thumbs.large) {
          thumbnailLargeKey = `thumbs/${uuidv4()}_l.webp`;
          await this.fileStorage.upload(thumbnailLargeKey, thumbs.large, 'image/webp');
          thumbnailLargeUrl = this.fileStorage.getPublicUrl(thumbnailLargeKey);
        }
      } else if (fileType === 'video') {
        const thumbs = await this.thumbnailService.generateVideoThumbnail(file.buffer);
        if (thumbs.medium) {
          thumbnailMediumKey = `thumbs/${uuidv4()}_m.webp`;
          await this.fileStorage.upload(thumbnailMediumKey, thumbs.medium, 'image/webp');
          thumbnailMediumUrl = this.fileStorage.getPublicUrl(thumbnailMediumKey);
        }
      }
    } catch (e) {
      this.logger.error('Thumbnail generation failed, continuing without thumbnails:', e);
    }

    // File deduplication: compute content hash (pixel-based for images)
    const sha256 = await this.computeContentHash(file.buffer, file.mimetype);
    this.logger.log(`[upload] content hash=${sha256} size=${file.size} mime=${file.mimetype}`);
    let fileRecordId: string | undefined;

    const existingRecord = await this.prisma.fileRecord.findUnique({ where: { sha256 } });
    if (existingRecord) {
      // Duplicate found: increment refCount, delete just-uploaded S3 objects, use existing record's data
      await this.prisma.fileRecord.update({ where: { id: existingRecord.id }, data: { refCount: { increment: 1 } } });
      // Delete the just-uploaded objects
      try {
        await this.fileStorage.delete(s3Key);
        if (thumbnailSmallKey) await this.fileStorage.delete(thumbnailSmallKey);
        if (thumbnailMediumKey) await this.fileStorage.delete(thumbnailMediumKey);
        if (thumbnailLargeKey) await this.fileStorage.delete(thumbnailLargeKey);
      } catch (e) {
        this.logger.error('Failed to delete duplicate S3 objects:', e);
      }
      fileRecordId = existingRecord.id;
      return {
        fileUrl: this.fileStorage.getPublicUrl(existingRecord.s3Key),
        fileName: file.originalname,
        fileSize: file.size,
        fileType,
        s3Key: existingRecord.s3Key,
        thumbnailSmallUrl: existingRecord.thumbnailSmall ? this.fileStorage.getPublicUrl(existingRecord.thumbnailSmall) : undefined,
        thumbnailMediumUrl: existingRecord.thumbnailMedium ? this.fileStorage.getPublicUrl(existingRecord.thumbnailMedium) : undefined,
        thumbnailLargeUrl: existingRecord.thumbnailLarge ? this.fileStorage.getPublicUrl(existingRecord.thumbnailLarge) : undefined,
        fileRecordId,
      };
    }

    // No duplicate: create new FileRecord
    const fileRecord = await this.prisma.fileRecord.create({
      data: {
        sha256,
        s3Key,
        mimeType: file.mimetype,
        size: file.size,
        thumbnailSmall: thumbnailSmallKey,
        thumbnailMedium: thumbnailMediumKey,
        thumbnailLarge: thumbnailLargeKey,
      },
    });
    fileRecordId = fileRecord.id;

    // Background video transcoding (fire-and-forget)
    if (fileType === 'video') {
      this.videoTranscode.transcodeToH264(s3Key).then(async (result) => {
        if (result) {
          await this.prisma.fileRecord.update({
            where: { id: fileRecord.id },
            data: { size: result.size, mimeType: 'video/mp4' },
          });
        }
      }).catch((e) => this.logger.error('Background transcode failed:', e));
    }

    return {
      fileUrl,
      fileName: file.originalname,
      fileSize: file.size,
      fileType,
      s3Key,
      thumbnailSmallUrl,
      thumbnailMediumUrl,
      thumbnailLargeUrl,
      fileRecordId,
    };
  }

  // ─── File download (streams from S3, no auth required for URLs embedded in messages) ───

  @Public()
  @Get('files/download')
  async downloadFile(
    @Query('key') key: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    if (!key) throw new ForbiddenException('key is required');
    try {
      const { stream, contentType, contentLength } = await this.fileStorage.getObject(key);
      const etag = `"${createHash('md5').update(key).digest('hex')}"`;
      // Return 304 if client has cached version
      if (res.req.headers['if-none-match'] === etag) {
        res.status(304).end();
        return;
      }
      const headers: Record<string, string | number> = {
        'Content-Type': contentType,
        'Cache-Control': 'public, max-age=604800, immutable',
        'ETag': etag,
      };
      if (contentLength) headers['Content-Length'] = contentLength;
      res.set(headers);
      return new StreamableFile(stream);
    } catch {
      throw new NotFoundException('File not found');
    }
  }

  // ─── URL refresh (returns public backend URL for a given S3 key) ───

  @Get('files/url')
  getFileUrl(@Query('key') key: string) {
    if (!key) throw new ForbiddenException('key is required');
    return { url: this.fileStorage.getPublicUrl(key) };
  }

  // ─── Chunked upload (Phase 2) ───

  @Post('files/init')
  async initChunkedUpload(
    @Body() body: { fileName: string; fileSize: number; mimeType: string },
    @CurrentUser() user: any,
  ) {
    const ext = extname(body.fileName);
    const s3Key = `files/${uuidv4()}${ext}`;
    const uploadId = await this.fileStorage.createMultipartUpload(s3Key, body.mimeType);

    // S3 minimum part size is 5MB (except last part)
    const partSize = 5 * 1024 * 1024;
    const totalParts = Math.ceil(body.fileSize / partSize);

    // Store state in Redis (24h TTL)
    const state = {
      s3Key,
      uploadId,
      fileName: body.fileName,
      fileSize: body.fileSize,
      mimeType: body.mimeType,
      parts: [] as { PartNumber: number; ETag: string }[],
      totalParts,
      userId: user.sub,
    };
    await this.redis.setEx(`chunked:${uploadId}`, 86400, JSON.stringify(state));

    return { uploadId, s3Key, partSize, totalParts };
  }

  @Post('files/chunk')
  @UseInterceptors(
    FileInterceptor('chunk', {
      storage: memoryStorage(),
      limits: { fileSize: 6 * 1024 * 1024 },
    }),
  )
  async uploadChunk(
    @UploadedFile() chunk: Express.Multer.File,
    @Body('uploadId') uploadId: string,
    @Body('partNumber') partNumberStr: string,
  ) {
    const partNumber = parseInt(partNumberStr, 10);
    const raw = await this.redis.get(`chunked:${uploadId}`);
    if (!raw) throw new NotFoundException('Upload not found or expired');
    const state = JSON.parse(raw);

    const etag = await this.fileStorage.uploadPart(state.s3Key, uploadId, partNumber, chunk.buffer);

    state.parts.push({ PartNumber: partNumber, ETag: etag });
    await this.redis.setEx(`chunked:${uploadId}`, 86400, JSON.stringify(state));

    return { etag, partNumber };
  }

  @Post('files/complete')
  async completeChunkedUpload(@Body('uploadId') uploadId: string) {
    const raw = await this.redis.get(`chunked:${uploadId}`);
    if (!raw) throw new NotFoundException('Upload not found or expired');
    const state = JSON.parse(raw);

    // Sort parts by PartNumber
    state.parts.sort((a: any, b: any) => a.PartNumber - b.PartNumber);

    // Complete S3 multipart upload
    await this.fileStorage.completeMultipartUpload(state.s3Key, uploadId, state.parts);

    const fileUrl = this.fileStorage.getPublicUrl(state.s3Key);

    // Determine file type
    let fileType = 'document';
    if (state.mimeType.startsWith('image/')) fileType = 'image';
    else if (state.mimeType.startsWith('video/')) fileType = 'video';
    else if (state.mimeType.startsWith('audio/')) fileType = 'audio';

    // Download file from S3 for thumbnails and hashing
    let fileData: Buffer | undefined;
    let thumbnailSmallUrl: string | undefined;
    let thumbnailMediumUrl: string | undefined;
    let thumbnailLargeUrl: string | undefined;
    let thumbnailSmallKey: string | undefined;
    let thumbnailMediumKey: string | undefined;
    let thumbnailLargeKey: string | undefined;

    try {
      if (fileType === 'image' || fileType === 'video') {
        const { stream } = await this.fileStorage.getObject(state.s3Key);
        const chunks: Buffer[] = [];
        for await (const c of stream) chunks.push(Buffer.from(c));
        fileData = Buffer.concat(chunks);

        if (fileType === 'image') {
          const thumbs = await this.thumbnailService.generateImageThumbnails(fileData);
          if (thumbs.small) {
            thumbnailSmallKey = `thumbs/${uuidv4()}_s.webp`;
            await this.fileStorage.upload(thumbnailSmallKey, thumbs.small, 'image/webp');
            thumbnailSmallUrl = this.fileStorage.getPublicUrl(thumbnailSmallKey);
          }
          if (thumbs.medium) {
            thumbnailMediumKey = `thumbs/${uuidv4()}_m.webp`;
            await this.fileStorage.upload(thumbnailMediumKey, thumbs.medium, 'image/webp');
            thumbnailMediumUrl = this.fileStorage.getPublicUrl(thumbnailMediumKey);
          }
          if (thumbs.large) {
            thumbnailLargeKey = `thumbs/${uuidv4()}_l.webp`;
            await this.fileStorage.upload(thumbnailLargeKey, thumbs.large, 'image/webp');
            thumbnailLargeUrl = this.fileStorage.getPublicUrl(thumbnailLargeKey);
          }
        } else if (fileType === 'video') {
          const thumbs = await this.thumbnailService.generateVideoThumbnail(fileData);
          if (thumbs.medium) {
            thumbnailMediumKey = `thumbs/${uuidv4()}_m.webp`;
            await this.fileStorage.upload(thumbnailMediumKey, thumbs.medium, 'image/webp');
            thumbnailMediumUrl = this.fileStorage.getPublicUrl(thumbnailMediumKey);
          }
        }
      }
    } catch (e) {
      this.logger.error('Thumbnail generation failed for chunked upload:', e);
    }

    // File deduplication: compute SHA-256
    // If we didn't download the file yet (non-image/video), download it now for hashing
    if (!fileData) {
      try {
        const { stream } = await this.fileStorage.getObject(state.s3Key);
        const chunks: Buffer[] = [];
        for await (const c of stream) chunks.push(Buffer.from(c));
        fileData = Buffer.concat(chunks);
      } catch (e) {
        this.logger.error('Failed to download file for hashing:', e);
      }
    }

    let fileRecordId: string | undefined;

    if (fileData) {
      const sha256 = await this.computeContentHash(fileData, state.mimeType);
      this.logger.log(`[chunked-complete] content hash=${sha256} size=${state.fileSize} mime=${state.mimeType}`);
      const existingRecord = await this.prisma.fileRecord.findUnique({ where: { sha256 } });

      if (existingRecord) {
        // Duplicate found: increment refCount, delete just-uploaded S3 objects
        await this.prisma.fileRecord.update({ where: { id: existingRecord.id }, data: { refCount: { increment: 1 } } });
        try {
          await this.fileStorage.delete(state.s3Key);
          if (thumbnailSmallKey) await this.fileStorage.delete(thumbnailSmallKey);
          if (thumbnailMediumKey) await this.fileStorage.delete(thumbnailMediumKey);
          if (thumbnailLargeKey) await this.fileStorage.delete(thumbnailLargeKey);
        } catch (e) {
          this.logger.error('Failed to delete duplicate S3 objects:', e);
        }
        fileRecordId = existingRecord.id;

        // Clean up Redis
        await this.redis.del(`chunked:${uploadId}`);

        return {
          fileUrl: this.fileStorage.getPublicUrl(existingRecord.s3Key),
          fileName: state.fileName,
          fileSize: state.fileSize,
          fileType,
          s3Key: existingRecord.s3Key,
          thumbnailSmallUrl: existingRecord.thumbnailSmall ? this.fileStorage.getPublicUrl(existingRecord.thumbnailSmall) : undefined,
          thumbnailMediumUrl: existingRecord.thumbnailMedium ? this.fileStorage.getPublicUrl(existingRecord.thumbnailMedium) : undefined,
          thumbnailLargeUrl: existingRecord.thumbnailLarge ? this.fileStorage.getPublicUrl(existingRecord.thumbnailLarge) : undefined,
          fileRecordId,
        };
      }

      // No duplicate: create new FileRecord
      const fileRecord = await this.prisma.fileRecord.create({
        data: {
          sha256,
          s3Key: state.s3Key,
          mimeType: state.mimeType,
          size: state.fileSize,
          thumbnailSmall: thumbnailSmallKey,
          thumbnailMedium: thumbnailMediumKey,
          thumbnailLarge: thumbnailLargeKey,
        },
      });
      fileRecordId = fileRecord.id;

      // Background video transcoding (fire-and-forget)
      if (fileType === 'video') {
        this.videoTranscode.transcodeToH264(state.s3Key).then(async (result) => {
          if (result) {
            await this.prisma.fileRecord.update({
              where: { id: fileRecord.id },
              data: { size: result.size, mimeType: 'video/mp4' },
            });
          }
        }).catch((e) => this.logger.error('Background transcode failed:', e));
      }
    }

    // Clean up Redis
    await this.redis.del(`chunked:${uploadId}`);

    return {
      fileUrl,
      fileName: state.fileName,
      fileSize: state.fileSize,
      fileType,
      s3Key: state.s3Key,
      thumbnailSmallUrl,
      thumbnailMediumUrl,
      thumbnailLargeUrl,
      fileRecordId,
    };
  }

  @Delete('files/:uploadId')
  async abortChunkedUpload(@Param('uploadId') uploadId: string) {
    const raw = await this.redis.get(`chunked:${uploadId}`);
    if (!raw) throw new NotFoundException('Upload not found');
    const state = JSON.parse(raw);

    await this.fileStorage.abortMultipartUpload(state.s3Key, uploadId);
    await this.redis.del(`chunked:${uploadId}`);

    return { ok: true };
  }

  @Post('call-ended')
  async endCall(
    @Body('conversationId') conversationId: string,
    @Body('roomName') roomName: string,
    @CurrentUser() user: any,
  ) {
    await this.gateway.endCallFromHttp(user.sub, conversationId, roomName);
    return { ok: true };
  }




  // ─── Channels ───

  @Post("channels")
  async createChannel(
    @Body("name") name: string,
    @Body("description") description: string,
    @Body("avatarUrl") avatarUrl: string,
    @CurrentUser() user: any,
  ) {
    return this.service.createChannel(user.sub, name, description, avatarUrl);
  }

  @Post("channels/:id/subscribe")
  async subscribe(@Param("id") id: string, @CurrentUser() user: any) {
    return this.service.subscribeToChannel(id, user.sub);
  }

  @Delete("channels/:id/subscribe")
  async unsubscribe(@Param("id") id: string, @CurrentUser() user: any) {
    return this.service.unsubscribeFromChannel(id, user.sub);
  }

  // ─── Polls ───

  @Post("conversations/:id/poll")
  async createPoll(
    @Param("id") id: string,
    @Body("question") question: string,
    @Body("options") options: string[],
    @Body("isAnonymous") isAnonymous: boolean,
    @Body("isMultiple") isMultiple: boolean,
    @CurrentUser() user: any,
  ) {
    const result = await this.service.createPoll(id, user.sub, question, options, isAnonymous, isMultiple);
    // Emit to conversation via gateway
    this.gateway.server.to(id).emit("new_message", {
      ...result.message,
      senderName: await this.service.getUserDisplayName(user.sub),
      reactions: [],
      poll: result.poll,
    });
    return result;
  }

  @Post("polls/:optionId/vote")
  async votePoll(@Param("optionId") optionId: string, @CurrentUser() user: any) {
    return this.service.votePoll(optionId, user.sub);
  }

  @Get("messages/:messageId/poll")
  async getPoll(@Param("messageId") messageId: string) {
    return this.service.getPollByMessageId(messageId);
  }

  // ─── Threads ───

  @Get("conversations/:convId/messages/:msgId/thread")
  async getThread(@Param("convId") convId: string, @Param("msgId") msgId: string) {
    const replies = await this.service.getThreadReplies(msgId);
    return replies.map(r => ({
      ...r,
      senderName: r.sender?.profile?.firstName
        ? r.sender.profile.firstName + (r.sender.profile.lastName ? " " + r.sender.profile.lastName : "")
        : r.sender?.username || "User",
      senderAvatar: r.sender?.profile?.avatarUrl || null,
    }));
  }

  @Post("conversations/:convId/messages/:msgId/thread")
  async sendThreadReply(
    @Param("convId") convId: string,
    @Param("msgId") msgId: string,
    @Body("content") content: string,
    @CurrentUser() user: any,
  ) {
    return this.service.sendThreadReply(convId, user.sub, content, msgId);
  }

  // ─── Topics ───

  @Get("conversations/:id/topics")
  async getTopics(@Param("id") id: string) {
    return this.service.getTopics(id);
  }

  @Post("conversations/:id/topics")
  async createTopic(
    @Param("id") id: string,
    @Body("title") title: string,
    @Body("icon") icon: string,
    @CurrentUser() user: any,
  ) {
    return this.service.createTopic(id, user.sub, title, icon);
  }

  @Delete("topics/:topicId")
  async deleteTopic(@Param("topicId") topicId: string, @CurrentUser() user: any) {
    await this.service.deleteTopic(topicId, user.sub);
    return { ok: true };
  }
}
