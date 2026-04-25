import { Injectable, Logger } from '@nestjs/common';
import { SipClient } from 'livekit-server-sdk';

const LK_HOST = process.env.LIVEKIT_HOST_OUTBOUND || 'https://ru.id.taler.tirol';
const LK_API_KEY = process.env.LIVEKIT_API_KEY_OUTBOUND || 'devkey278c50b6c7ef4dab';
const LK_API_SECRET = process.env.LIVEKIT_API_SECRET_OUTBOUND || '71658877e5b5f568313c7394c57a566ee6acd66ccf8e3f900237ac88d7e649e7';
const SIP_TRUNK_ID = process.env.SIP_TRUNK_ID || '';

@Injectable()
export class SipService {
  private readonly logger = new Logger(SipService.name);
  private readonly sipClient = new SipClient(LK_HOST, LK_API_KEY, LK_API_SECRET);

  isConfigured(): boolean {
    return !!SIP_TRUNK_ID;
  }

  async dialOutbound(roomName: string, phoneNumber: string): Promise<{ participantId: string }> {
    this.logger.log(`[SIP] dialOutbound room=${roomName} phone=${phoneNumber} trunk=${SIP_TRUNK_ID}`);
    try {
      const result = await this.sipClient.createSipParticipant(
        SIP_TRUNK_ID,
        phoneNumber,
        roomName,
        {
          participantIdentity: `sip-${phoneNumber}`,
          participantName: phoneNumber,
          waitUntilAnswered: true,
          timeout: 90,
        },
      );
      this.logger.log(`[SIP] Call connected: ${result?.participantIdentity}`);
      return { participantId: result?.participantIdentity || `sip-${phoneNumber}` };
    } catch (e) {
      this.logger.error(`[SIP] dialOutbound failed: ${(e as Error).message}`);
      throw e;
    }
  }
}
