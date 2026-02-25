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
    // Prefer file path over inline JSON (more reliable with special chars)
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

  async sendCallInvite(fcmToken: string, fromName: string, roomName: string, conversationId: string): Promise<void> {
    if (!this.initialized || !fcmToken) return;
    try {
      await admin.messaging().send({
        token: fcmToken,
        data: {
          type: 'call_invite',
          roomName,
          conversationId,
          fromName,
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
              alert: {
                title: 'Входящий звонок',
                body: `${fromName} звонит вам`,
              },
              sound: 'default',
              contentAvailable: true,
            },
          },
          headers: {
            'apns-priority': '10',
            'apns-push-type': 'alert',
          },
        },
      });
    } catch (e) {
      this.logger.error('FCM send error:', e);
    }
  }
}
