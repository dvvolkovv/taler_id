import { Injectable, Logger } from '@nestjs/common';
import * as admin from 'firebase-admin';
import * as fs from 'fs';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class FcmService {
  private readonly logger = new Logger(FcmService.name);
  private initialized = false;

  constructor(private readonly prisma: PrismaService) {
    this.init();
  }

  /**
   * Detects FCM "token is stale" errors and nulls the `fcmToken` column for
   * any user whose token matches the bad value. Wrapped in `.catch(() => {})`
   * downstream so push fan-out is never blocked by cleanup failures.
   *
   * Matches all known forms:
   *   - 'messaging/registration-token-not-registered'  (current Admin SDK)
   *   - 'messaging/invalid-registration-token'         (current Admin SDK)
   *   - 'NotRegistered'                                (legacy FCM HTTP v1 / GCM)
   *   - 'InvalidRegistration'                          (legacy GCM)
   */
  private async handleSendError(token: string | undefined, err: any): Promise<void> {
    if (!token) return;
    const code: string | undefined =
      err?.code ?? err?.errorInfo?.code ?? err?.error?.code;
    const messageText: string = String(err?.message ?? '');
    const STALE_CODES = new Set([
      'messaging/registration-token-not-registered',
      'messaging/invalid-registration-token',
      'NotRegistered',
      'InvalidRegistration',
    ]);
    const isStale =
      (code && STALE_CODES.has(code)) ||
      // Legacy SDKs sometimes surface the bare string in the message body.
      messageText.includes('NotRegistered') ||
      messageText.includes('InvalidRegistration') ||
      messageText.includes('registration-token-not-registered') ||
      messageText.includes('invalid-registration-token');
    if (!isStale) return;
    this.logger.warn(
      `FCM token stale (code=${code ?? 'n/a'}) — clearing User.fcmToken matches for token=${token.substring(0, 12)}…`,
    );
    try {
      const result = await this.prisma.user.updateMany({
        where: { fcmToken: token },
        data: { fcmToken: null },
      });
      this.logger.warn(`FCM token cleanup: cleared fcmToken on ${result.count} user row(s)`);
    } catch (cleanupErr) {
      this.logger.error(`FCM token cleanup failed: ${cleanupErr}`);
    }
  }

  private init() {
    const serviceAccountPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH;
    const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

    let serviceAccount: object | null = null;

    if (serviceAccountPath) {
      try {
        const content = fs.readFileSync(serviceAccountPath, 'utf8');
        serviceAccount = JSON.parse(content);
      } catch (e) {
        this.logger.error('Failed to read FIREBASE_SERVICE_ACCOUNT_PATH:', e);
        return;
      }
    } else if (serviceAccountJson) {
      try {
        serviceAccount = JSON.parse(serviceAccountJson);
      } catch (e) {
        this.logger.error('Failed to parse FIREBASE_SERVICE_ACCOUNT_JSON:', e);
        return;
      }
    } else {
      this.logger.warn(
        'Neither FIREBASE_SERVICE_ACCOUNT_PATH nor FIREBASE_SERVICE_ACCOUNT_JSON set — FCM push disabled',
      );
      return;
    }

    try {
      if (admin.apps.length === 0) {
        admin.initializeApp({
          credential: admin.credential.cert(
            serviceAccount as admin.ServiceAccount,
          ),
        });
      }
      this.initialized = true;
      this.logger.log('Firebase Admin initialized');
    } catch (e) {
      this.logger.error('Failed to init Firebase Admin:', e);
    }
  }

  async sendCallInvite(
    fcmToken: string,
    fromName: string,
    roomName: string,
    conversationId: string,
    e2eeKey?: string,
    fromAvatar?: string,
  ): Promise<void> {
    if (!this.initialized || !fcmToken) return;
    try {
      await admin.messaging().send({
        token: fcmToken,
        data: {
          type: 'call_invite',
          roomName,
          conversationId,
          fromName,
          ...(e2eeKey ? { e2eeKey } : {}),
          ...(fromAvatar ? { fromAvatar } : {}),
        },
        android: {
          priority: 'high',
          notification: {
            title: 'Входящий звонок',
            body: `${fromName} звонит вам`,
            channelId: 'calls',
            priority: 'max',
            defaultSound: true,
          },
        },
        apns: {
          payload: {
            aps: {
              contentAvailable: true,
            },
          },
          headers: {
            'apns-priority': '5',
            'apns-push-type': 'background',
          },
        },
      });
    } catch (e) {
      this.logger.error('FCM sendCallInvite error:', e);
      this.handleSendError(fcmToken, e).catch(() => {});
    }
  }

  async sendNewMessage(
    fcmToken: string,
    fromName: string,
    body: string,
    conversationId: string,
  ): Promise<void> {
    if (!this.initialized || !fcmToken) return;
    const truncated = body.length > 100 ? body.substring(0, 100) + '…' : body;
    try {
      await admin.messaging().send({
        token: fcmToken,
        data: {
          type: 'new_message',
          conversationId,
        },
        notification: {
          title: fromName,
          body: truncated,
        },
        android: {
          priority: 'high',
          notification: {
            channelId: 'messages',
            defaultSound: true,
          },
        },
        apns: {
          payload: {
            aps: {
              sound: 'default',
              alert: {
                title: fromName,
                body: truncated,
              },
            },
          },
          headers: {
            'apns-priority': '10',
            'apns-push-type': 'alert',
          },
        },
      });
    } catch (e) {
      this.logger.error('FCM sendNewMessage error:', e);
      this.handleSendError(fcmToken, e).catch(() => {});
    }
  }

  async sendCalendarInvite(
    fcmToken: string,
    title: string,
    body: string,
    eventId: string,
  ): Promise<void> {
    if (!this.initialized || !fcmToken) return;
    try {
      await admin.messaging().send({
        token: fcmToken,
        data: { type: 'calendar_invite', eventId },
        notification: { title, body },
        android: { priority: 'high' as const },
        apns: { payload: { aps: { sound: 'default' } } },
      });
    } catch (e: any) {
      this.logger.error('FCM sendCalendarInvite error:', e);
      this.handleSendError(fcmToken, e).catch(() => {});
    }
  }

  async sendCalendarReminder(
    fcmToken: string,
    title: string,
    body: string,
    eventId: string,
  ): Promise<void> {
    if (!this.initialized || !fcmToken) return;
    try {
      await admin.messaging().send({
        token: fcmToken,
        data: { type: 'calendar_reminder', eventId },
        notification: { title, body },
        android: { priority: 'high' as const },
        apns: { payload: { aps: { sound: 'default' } } },
      });
    } catch (e: any) {
      this.logger.error('FCM sendCalendarReminder error:', e);
      this.handleSendError(fcmToken, e).catch(() => {});
    }
  }

  async sendCalendarUpdated(fcmToken: string): Promise<void> {
    if (!this.initialized || !fcmToken) return;
    try {
      await admin.messaging().send({
        token: fcmToken,
        data: { type: 'calendar_updated' },
        android: { priority: 'high' as const },
        apns: {
          payload: { aps: { 'content-available': 1 } },
          headers: { 'apns-push-type': 'background', 'apns-priority': '5' },
        },
      });
    } catch (e: any) {
      this.handleSendError(fcmToken, e).catch(() => {});
    }
  }

  async sendContactRequest(fcmToken: string, fromName: string): Promise<void> {
    if (!this.initialized || !fcmToken) return;
    try {
      await admin.messaging().send({
        token: fcmToken,
        data: {
          type: 'contact_request',
        },
        notification: {
          title: 'Запрос на общение',
          body: `${fromName} хочет начать общение с вами`,
        },
        android: {
          priority: 'high',
          notification: {
            channelId: 'messages',
            defaultSound: true,
          },
        },
        apns: {
          payload: {
            aps: {
              sound: 'default',
              alert: {
                title: 'Запрос на общение',
                body: `${fromName} хочет начать общение с вами`,
              },
            },
          },
          headers: {
            'apns-priority': '10',
            'apns-push-type': 'alert',
          },
        },
      });
    } catch (e) {
      this.logger.error('FCM sendContactRequest error:', e);
      this.handleSendError(fcmToken, e).catch(() => {});
    }
  }

  async sendKeyUpdate(userId: string): Promise<void> {
    if (!this.initialized) return;
    try {
      await admin.messaging().send({
        topic: `mesh-keys/${userId}`,
        data: {
          type: 'mesh_key_update',
          userId,
          ts: String(Date.now()),
        },
        // Data-only push — no notification block intentionally.
        android: { priority: 'high' as const },
        apns: {
          payload: { aps: { contentAvailable: true } },
          headers: { 'apns-priority': '5', 'apns-push-type': 'background' },
        },
      });
    } catch (e) {
      this.logger.warn(`sendKeyUpdate failed for ${userId}: ${e}`);
    }
  }

  /**
   * Group voice call invite via FCM (Android). Stub for Phase 1 Task 4 —
   * Task 14 fills in the body: fetch the user's FCM token(s), build a
   * data-only message (`type: 'group_call_invite'`) including groupCallId,
   * host display name, invitee count, and dispatch.
   */
  async sendGroupCallInvite(
    userId: string,
    payload: {
      groupCallId: string;
      host: { id: string; displayName: string; avatarUrl?: string | null };
      inviteeCount: number;
    },
  ): Promise<void> {
    if (!this.initialized) return;

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { fcmToken: true },
    });
    const fcmToken = user?.fcmToken;
    if (!fcmToken) {
      this.logger.debug(
        `No FCM token for user ${userId} — skipping FCM group-call push`,
      );
      return;
    }

    try {
      await admin.messaging().send({
        token: fcmToken,
        android: {
          priority: 'high',
          ttl: 30 * 1000, // ringing TTL
        },
        data: {
          type: 'group_call_invite',
          groupCallId: payload.groupCallId,
          hostId: payload.host.id,
          hostDisplayName: payload.host.displayName,
          hostAvatarUrl: payload.host.avatarUrl ?? '',
          inviteeCount: String(payload.inviteeCount),
        },
      });
    } catch (e: any) {
      this.logger.error(
        `FCM sendGroupCallInvite error for ${userId}: ${e?.message ?? e}`,
      );
      this.handleSendError(fcmToken, e).catch(() => {});
    }
  }

  async sendCallCancelled(
    fcmToken: string,
    roomName: string,
    fromName?: string,
  ): Promise<void> {
    if (!this.initialized || !fcmToken) return;
    try {
      await admin.messaging().send({
        token: fcmToken,
        data: {
          type: 'call_cancelled',
          roomName,
          fromName: fromName || 'Неизвестный',
        },
        android: {
          priority: 'high',
        },
        apns: {
          payload: { aps: { contentAvailable: true } },
          headers: {
            'apns-priority': '5',
            'apns-push-type': 'background',
          },
        },
      });
    } catch (e) {
      this.logger.error('FCM sendCallCancelled error:', e);
      this.handleSendError(fcmToken, e).catch(() => {});
    }
  }
}
