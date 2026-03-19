import {
  Controller, Get, Post, Patch, Delete, Body, Param, Query, UseGuards,
  UseInterceptors, UploadedFile, ForbiddenException,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';
import { v4 as uuidv4 } from 'uuid';
import { MessengerService } from './messenger.service';
import { MessengerGateway } from './messenger.gateway';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { CreateGroupDto } from './dto/create-group.dto';
import { UpdateGroupDto } from './dto/update-group.dto';
import { AddMembersDto } from './dto/add-members.dto';
import { ChangeGroupRoleDto } from './dto/change-role.dto';

@Controller('messenger')
@UseGuards(JwtAuthGuard)
export class MessengerController {
  constructor(
    private readonly service: MessengerService,
    private readonly gateway: MessengerGateway,
  ) {}

  // ─── Direct conversations ───

  @Post('conversations')
  async create(@Body('participantId') participantId: string, @CurrentUser() user: any) {
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
    return result;
  }

  @Get('contacts/requests')
  getContactRequests(@CurrentUser() user: any) {
    return this.service.getContactRequests(user.sub);
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
    return result;
  }

  @Patch('contacts/requests/:id/reject')
  async rejectContactRequest(@Param('id') id: string, @CurrentUser() user: any) {
    return this.service.rejectContactRequest(id, user.sub);
  }

  // ─── User search ───

  @Get('users/search')
  search(@Query('q') q: string, @CurrentUser() user: any) {
    if (!q || q.length < 2) return [];
    return this.service.searchUsers(q, user.sub);
  }

  // ─── File upload ───

  @Post('files')
  @UseInterceptors(
    FileInterceptor('file', {
      storage: diskStorage({
        destination: '/home/dvolkov/taler-id/uploads/files',
        filename: (_req, file, cb) => {
          cb(null, `${uuidv4()}${extname(file.originalname)}`);
        },
      }),
      limits: { fileSize: 100 * 1024 * 1024 },
    }),
  )
  uploadFile(@UploadedFile() file: Express.Multer.File) {
    const fileType = file.mimetype.startsWith('image/') ? 'image' : 'document';
    return {
      fileUrl: `https://id.taler.tirol/uploads/files/${file.filename}`,
      fileName: file.originalname,
      fileSize: file.size,
      fileType,
    };
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
}
