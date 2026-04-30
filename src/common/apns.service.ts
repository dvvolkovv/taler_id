import { Injectable, Logger } from '@nestjs/common';
import * as apn from 'node-apn';
import { v4 as uuidv4 } from 'uuid';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class ApnsService {
  private readonly logger = new Logger(ApnsService.name);
  private productionProvider?: apn.Provider;
  private sandboxProvider?: apn.Provider;

  constructor(private readonly prisma: PrismaService) {
    const keyPath = process.env.APNS_KEY_PATH;
    const keyId = process.env.APNS_KEY_ID;
    const teamId = process.env.APNS_TEAM_ID;
    if (keyPath && keyId && teamId) {
      const tokenConfig = { key: keyPath, keyId, teamId };
      this.productionProvider = new apn.Provider({
        token: tokenConfig,
        production: true,
      });
      this.sandboxProvider = new apn.Provider({
        token: tokenConfig,
        production: false,
      });
      this.logger.log('APNs providers initialized (production + sandbox)');
    } else {
      this.logger.warn(
        'APNs not configured (APNS_KEY_PATH/APNS_KEY_ID/APNS_TEAM_ID missing) — VoIP push disabled',
      );
    }
  }

  async sendVoIPCallInvite(
    voipToken: string,
    data: {
      nameCaller: string;
      roomName: string;
      conversationId: string;
      e2eeKey?: string;
    },
  ): Promise<void> {
    if (!this.productionProvider || !this.sandboxProvider) return;
    const bundleId = process.env.APNS_BUNDLE_ID ?? 'tirol.taler.talerIdMobile';

    const buildNote = () => {
      const note = new apn.Notification();
      note.topic = `${bundleId}.voip`;
      note.pushType = 'voip';
      note.priority = 10;
      note.expiry = Math.floor(Date.now() / 1000) + 30;
      note.payload = {
        id: uuidv4(),
        nameCaller: data.nameCaller,
        appName: 'Taler ID',
        handle: '',
        type: 0,
        extra: {
          roomName: data.roomName,
          conversationId: data.conversationId,
          ...(data.e2eeKey ? { e2eeKey: data.e2eeKey } : {}),
        },
      };
      return note;
    };

    try {
      // Try production first
      const result = await this.productionProvider.send(buildNote(), voipToken);
      if (result.sent.length > 0) {
        this.logger.log('APNs VoIP sent via production');
        return;
      }
      const failure = result.failed[0];
      const reason = failure?.response?.reason;
      // BadDeviceToken means the token is for sandbox (dev build) — retry with sandbox
      if (reason === 'BadDeviceToken' || reason === 'DeviceTokenNotForTopic') {
        this.logger.warn(
          `APNs production failed (${reason}), retrying with sandbox...`,
        );
        const sandboxResult = await this.sandboxProvider.send(
          buildNote(),
          voipToken,
        );
        if (sandboxResult.sent.length > 0) {
          this.logger.log('APNs VoIP sent via sandbox (dev build token)');
        } else {
          this.logger.error(
            'APNs sandbox also failed:',
            JSON.stringify(sandboxResult.failed[0]),
          );
        }
      } else {
        this.logger.error('APNs VoIP send failed:', JSON.stringify(failure));
      }
    } catch (e) {
      this.logger.error('APNs sendVoIPCallInvite error:', e);
    }
  }

  /**
   * Group voice call invite via VoIP push (iOS CallKit). Stub for Phase 1
   * Task 4 — Task 14 fills in the body: fetch the user's VoIP token(s), build
   * an APNs payload similar to sendVoIPCallInvite (pushType `voip`,
   * topic `${bundleId}.voip`), include `groupCallId` + host info + invitee
   * count in `extra`, and dispatch via production with sandbox fallback.
   */
  async sendGroupCallInvite(
    userId: string,
    payload: {
      groupCallId: string;
      host: { id: string; displayName: string; avatarUrl?: string | null };
      inviteeCount: number;
      livekitRoomName: string;
    },
  ): Promise<void> {
    if (!this.productionProvider || !this.sandboxProvider) return;

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { voipToken: true },
    });
    const voipToken = user?.voipToken;
    if (!voipToken) {
      this.logger.debug(`No VoIP token for user ${userId} — skipping APNs group-call push`);
      return;
    }

    const bundleId = process.env.APNS_BUNDLE_ID ?? 'tirol.taler.talerIdMobile';

    // Display: "Алиса Иванова" + "Группа: + N ещё" subtitle
    const callerName = payload.host.displayName;
    const groupSuffix =
      payload.inviteeCount > 1 ? ` + ${payload.inviteeCount - 1} ещё` : '';

    const buildNote = () => {
      const note = new apn.Notification();
      note.topic = `${bundleId}.voip`;
      note.pushType = 'voip';
      note.priority = 10;
      note.expiry = Math.floor(Date.now() / 1000) + 30; // ringing TTL = 30s
      note.payload = {
        id: uuidv4(),
        // CallKit metadata
        type: 'group_call_invite',
        groupCallId: payload.groupCallId,
        nameCaller: `${callerName}${groupSuffix}`,
        hostUserId: payload.host.id,
        hostAvatarUrl: payload.host.avatarUrl ?? null,
        inviteeCount: payload.inviteeCount,
        livekitRoomName: payload.livekitRoomName,
      };
      return note;
    };

    try {
      const result = await this.productionProvider.send(buildNote(), voipToken);
      if (result.failed.length > 0) {
        const reason = result.failed[0].response?.reason;
        if (reason === 'BadDeviceToken') {
          // Sandbox fallback (TestFlight / dev builds)
          const sandboxResult = await this.sandboxProvider.send(buildNote(), voipToken);
          if (sandboxResult.failed.length > 0) {
            this.logger.warn(
              `APNs group-call sandbox send failed for ${userId}: ${sandboxResult.failed[0].response?.reason}`,
            );
          }
        } else {
          this.logger.warn(
            `APNs group-call send failed for ${userId}: ${reason}`,
          );
        }
      }
    } catch (e: any) {
      this.logger.error(
        `APNs group-call send threw for ${userId}: ${e?.message ?? e}`,
      );
    }
  }
}
