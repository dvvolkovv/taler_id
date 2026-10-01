import { Injectable, Logger } from '@nestjs/common';

type Disconnector = (partnerId: string, userId: string) => Promise<void> | void;

/**
 * Мостик к шлюзу мессенджера: шлюз при старте регистрирует функцию «порвать
 * сокеты связки» (как AiTwinService.registerEmitters), и отзыв связки рвёт их
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
  async disconnectLink(partnerId: string, userId: string): Promise<void> {
    if (!this.disconnector) {
      // Отзыв из процесса без шлюза (скрипт, воркер): сокеты связки доживут до
      // истечения своего токена. Молчать об этом нельзя — обещан мгновенный разрыв.
      this.logger.warn(
        `sockets of partner link ${partnerId}:${userId} were not disconnected: messenger gateway is not registered in this process`,
      );
      return;
    }
    try {
      await this.disconnector(partnerId, userId);
    } catch (e) {
      this.logger.warn(
        `disconnect partner link ${partnerId}:${userId} failed: ${(e as Error).message}`,
      );
    }
  }
}
