import {
  Controller, Get, Post, Body, Param, Query, UseGuards,
  UseInterceptors, UploadedFile,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';
import { v4 as uuidv4 } from 'uuid';
import { MessengerService } from './messenger.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';

@Controller('messenger')
@UseGuards(JwtAuthGuard)
export class MessengerController {
  constructor(private readonly service: MessengerService) {}

  @Post('conversations')
  create(@Body('participantId') participantId: string, @CurrentUser() user: any) {
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

  @Get('users/search')
  search(@Query('q') q: string, @CurrentUser() user: any) {
    if (!q || q.length < 2) return [];
    return this.service.searchUsers(q, user.sub);
  }

  @Post('files')
  @UseInterceptors(
    FileInterceptor('file', {
      storage: diskStorage({
        destination: '/home/dvolkov/taler-id/uploads/files',
        filename: (_req, file, cb) => {
          cb(null, `${uuidv4()}${extname(file.originalname)}`);
        },
      }),
      limits: { fileSize: 20 * 1024 * 1024 }, // 20 MB
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
}
