import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import * as fs from 'fs';
import * as jwt from 'jsonwebtoken';
import { IS_PUBLIC_KEY } from '../common/decorators/public.decorator';
import { isApiAccessToken } from '../common/utils/access-token.util';
import { PARTNER_FORBIDDEN } from '../partner-core/partner.constants';
import { PartnerTokensService } from '../partner-core/partner-tokens.service';
import { PARTNER_ALLOWED_KEY, PartnerAllowedOptions } from './partner-allowed.decorator';
import { PartnerConversationScope } from './partner-conversation-scope.service';

/**
 * Вход в REST мессенджера по двум видам токена:
 *  - собственный токен входа TalerID — ровно как JwtAuthGuard до этого;
 *  - OAuth-токен партнёра со scope `messenger` — только в обработчики с
 *    @PartnerAllowed() и только к личным чатам и группам.
 * Партнёрский токен опаковый и не проходит jwt.verify, поэтому остальные
 * guard'ы TalerID (профиль, KYC, админка, голосовой прокси) его не пускают
 * без всяких правок.
 * Спека: docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md
 */
@Injectable()
export class MessengerAuthGuard implements CanActivate {
  private readonly publicKey: string;

  constructor(
    private readonly reflector: Reflector,
    private readonly partnerTokens: PartnerTokensService,
    private readonly scope: PartnerConversationScope,
    config: ConfigService,
  ) {
    const keyPath = config.get<string>('jwt.publicKeyPath') ?? '';
    this.publicKey = keyPath ? fs.readFileSync(keyPath, 'utf8') : '';
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const targets = [context.getHandler(), context.getClass()];
    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, targets)) return true;

    const req = context.switchToHttp().getRequest();
    const match = /^Bearer\s+(\S+)$/i.exec(String(req.headers?.authorization ?? ''));
    const token = match?.[1];
    if (!token) throw new UnauthorizedException('Invalid or expired token');

    const native = this.verifyNative(token);
    if (native) {
      req.user = native;
      return true;
    }

    const principal = await this.partnerTokens.verify(token);
    if (!principal) throw new UnauthorizedException('Invalid or expired token');

    const allowed = this.reflector.getAllAndOverride<PartnerAllowedOptions>(PARTNER_ALLOWED_KEY, targets);
    if (!allowed) throw new ForbiddenException(PARTNER_FORBIDDEN);
    req.user = { sub: principal.userId, partner: principal };
    if (allowed.conversationParam) await this.scope.assertConversation(req.params?.[allowed.conversationParam]);
    if (allowed.messageParam) await this.scope.assertMessage(req.params?.[allowed.messageParam]);
    return true;
  }

  private verifyNative(token: string): Record<string, unknown> | null {
    if (!this.publicKey) return null;
    try {
      const payload = jwt.verify(token, this.publicKey, { algorithms: ['RS256'] });
      // ID-токены OIDC подписаны тем же ключом — пропускаем только access.
      return isApiAccessToken(payload) ? (payload as Record<string, unknown>) : null;
    } catch {
      return null;
    }
  }
}
