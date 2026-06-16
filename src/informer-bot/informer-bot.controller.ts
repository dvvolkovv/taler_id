import {
  Controller,
  ForbiddenException,
  Post,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { InformerBotService } from './informer-bot.service';
import { InformerWatcher } from './informer.watcher';

@Controller('informer-bot')
export class InformerBotController {
  constructor(
    private readonly service: InformerBotService,
    private readonly watcher: InformerWatcher,
  ) {}

  @Post()
  @UseGuards(JwtAuthGuard)
  async getOrCreateChat(@CurrentUser() user: any) {
    try {
      const conversationId = await this.service.getOrCreateChat(user.sub);
      return { conversationId };
    } catch (e: any) {
      if (e?.message === 'informer-access-denied') {
        throw new ForbiddenException('informer-access-denied');
      }
      throw e;
    }
  }

  @Post('debug/tick')
  @UseGuards(JwtAuthGuard)
  async debugTick() {
    if (process.env.INFORMER_DEBUG_TICK !== 'true') {
      throw new ForbiddenException('debug-tick-disabled');
    }
    return this.watcher.tickForTest();
  }
}
