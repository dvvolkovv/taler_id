import {
  BadRequestException, Body, Controller, Delete, Get, Param, ParseIntPipe, Post, Query, Res, UseGuards,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import type { Response } from 'express';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { MailAccountService } from './mail-account.service';
import { MailBridgeService } from './mail-bridge.service';
import { CreateAppPasswordDto, CreateMailAccountDto, SendMessageDto } from './dto/mail.dto';

@Controller('mail')
@UseGuards(JwtAuthGuard)
export class MailController {
  constructor(
    private readonly accounts: MailAccountService,
    private readonly bridge: MailBridgeService,
  ) {}

  // ── Аккаунт ────────────────────────────────────────────────

  @Get('availability')
  checkAvailability(@Query('localpart') localpart: string) {
    return this.accounts.checkAvailability(localpart);
  }

  @Post('account')
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  createAccount(@CurrentUser() user: any, @Body() dto: CreateMailAccountDto) {
    return this.accounts.createAccount(user.sub, dto.localpart);
  }

  @Get('account')
  getAccount(@CurrentUser() user: any) {
    return this.accounts.getAccount(user.sub);
  }

  // ── App-пароли ─────────────────────────────────────────────

  @Post('app-passwords')
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  createAppPassword(@CurrentUser() user: any, @Body() dto: CreateAppPasswordDto) {
    return this.accounts.createAppPassword(user.sub, dto.label);
  }

  @Get('app-passwords')
  listAppPasswords(@CurrentUser() user: any) {
    return this.accounts.listAppPasswords(user.sub);
  }

  @Delete('app-passwords/:id')
  async revokeAppPassword(@CurrentUser() user: any, @Param('id') id: string) {
    await this.accounts.revokeAppPassword(user.sub, id);
    return { ok: true };
  }

  // ── Папки ──────────────────────────────────────────────────

  @Get('folders')
  listFolders(@CurrentUser() user: any) {
    return this.bridge.listFolders(user.sub);
  }

  @Post('folders')
  async createFolder(@CurrentUser() user: any, @Body() dto: { name: string }) {
    await this.bridge.createFolder(user.sub, dto.name);
    return { ok: true };
  }

  @Delete('folders')
  async deleteFolder(@CurrentUser() user: any, @Query('path') path: string) {
    if (!path) throw new BadRequestException('folder_path_required');
    await this.bridge.deleteFolder(user.sub, path);
    return { ok: true };
  }

  // ── Письма ─────────────────────────────────────────────────

  @Get('messages')
  listMessages(
    @CurrentUser() user: any,
    @Query('folder') folder?: string,
    @Query('beforeUid') beforeUid?: string,
  ) {
    return this.bridge.listMessages(user.sub, folder || 'INBOX', beforeUid ? Number(beforeUid) : undefined);
  }

  @Get('messages/:uid')
  getMessage(@CurrentUser() user: any, @Param('uid', ParseIntPipe) uid: number, @Query('folder') folder?: string) {
    return this.bridge.getMessage(user.sub, uid, folder || 'INBOX');
  }

  @Get('messages/:uid/attachments/:index')
  async getAttachment(
    @CurrentUser() user: any,
    @Param('uid', ParseIntPipe) uid: number,
    @Param('index', ParseIntPipe) index: number,
    @Res() res: Response,
    @Query('folder') folder?: string,
  ) {
    const att = await this.bridge.getAttachment(user.sub, uid, index, folder || 'INBOX');
    // C2: санитизация filename — только безопасные символы
    const safe = att.filename.replace(/[^\w.\- ]/g, '_');
    // C2: не отдавать image/* напрямую — всегда application/octet-stream для неизвестных типов
    const contentType = (att.contentType ?? '').startsWith('image/') ? att.contentType : 'application/octet-stream';
    res.setHeader('Content-Type', contentType);
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${safe}"; filename*=UTF-8''${encodeURIComponent(att.filename)}`,
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.send(att.content);
  }

  @Post('messages')
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  async sendMessage(@CurrentUser() user: any, @Body() dto: SendMessageDto) {
    await this.bridge.sendMessage(user.sub, dto);
    return { ok: true };
  }

  @Post('messages/:uid/read')
  async markRead(@CurrentUser() user: any, @Param('uid', ParseIntPipe) uid: number, @Query('folder') folder?: string) {
    await this.bridge.setSeen(user.sub, uid, true, folder || 'INBOX');
    return { ok: true };
  }

  @Post('messages/:uid/unread')
  async markUnread(@CurrentUser() user: any, @Param('uid', ParseIntPipe) uid: number, @Query('folder') folder?: string) {
    await this.bridge.setSeen(user.sub, uid, false, folder || 'INBOX');
    return { ok: true };
  }

  @Post('messages/:uid/move')
  async moveMessage(
    @CurrentUser() user: any,
    @Param('uid', ParseIntPipe) uid: number,
    @Body() dto: { fromFolder?: string; toFolder: string },
  ) {
    if (!dto?.toFolder) throw new BadRequestException('to_folder_required');
    await this.bridge.moveMessage(user.sub, uid, dto.fromFolder || 'INBOX', dto.toFolder);
    return { ok: true };
  }

  @Delete('messages/:uid')
  async deleteMessage(@CurrentUser() user: any, @Param('uid', ParseIntPipe) uid: number, @Query('folder') folder?: string) {
    await this.bridge.deleteMessage(user.sub, uid, folder || 'INBOX');
    return { ok: true };
  }
}
