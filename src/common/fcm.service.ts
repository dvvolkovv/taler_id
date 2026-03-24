import { Injectable, Logger } from '@nestjs/common';
import * as admin from 'firebase-admin';
import * as fs from 'fs';

@Injectable()
export class FcmService {
  private readonly logger = new Logger(FcmService.name);
  private initialized = false;

  constructor() {
    this.init();
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
      this.logger.warn('Neither FIREBASE_SERVICE_ACCOUNT_PATH nor FIREBASE_SERVICE_ACCOUNT_JSON set — FCM push disabled');
      return;
    }

    try {
      if (admin.apps.length === 0) {
        admin.initializeApp({ credential: admin.credential.cert(serviceAccount as admin.ServiceAccount) });
      }
      this.initialized = true;
      this.logger.log('Firebase Admin initialized');
    } catch (e) {
      this.logger.error('Failed to init Firebase Admin:', e);
    }
  }

  async sendCallInvite(fcmToken: string, fromName: string, roomName: string, conversationId: string, e2eeKey?: string): Promise<void> {
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
    }
  }

  async sendNewMessage(fcmToken: string, fromName: string, body: string, conversationId: string): Promise<void> {
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
    }
  }

  async sendCallCancelled(fcmToken: string, roomName: string, fromName?: string): Promise<void> {
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
    }
  }
}

