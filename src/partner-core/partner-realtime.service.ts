import { Injectable, Logger } from '@nestjs/common';

type Disconnector = (grantId: string) => Promise<void> | void;

/**
 * Мостик к шлюзу мессенджера: шлюз при старте регистрирует функцию «порвать
 * сокеты гранта» (как AiTwinService.registerEmitters), и отзыв связки рвёт их
 * на всех нодах через Redis-адаптер Socket.IO, не завися от MessengerModule.
 */
@Injectable()
export class PartnerRealtimeService {
  private readonly logger = new Logger(PartnerRealtimeService.name);
  private disconnector: Disconnector | null = null;

  registerDisconnector(fn: Disconnector): void {
    this.disconnector = fn;
  }

  /** Ошибка разрыва не должна мешать отзыву: токены к этому моменту уже погашены. */
  async disconnectGrant(grantId: string): Promise<void> {
    if (!this.disconnector) return;
    try {
      await this.disconnector(grantId);
    } catch (e) {
      this.logger.warn(`disconnect grant ${grantId} failed: ${(e as Error).message}`);
    }
  }
}
