import { Injectable, Logger } from '@nestjs/common';
import { SipClient } from 'livekit-server-sdk';

const LK_HOST = process.env.LIVEKIT_HOST || 'http://localhost:7880';
const LK_API_KEY = process.env.LIVEKIT_API_KEY || 'lkdevkey';
const LK_API_SECRET = process.env.LIVEKIT_API_SECRET || 'lkSecret2024TalerID';

// Created via livekit-cli: ST_23t6SdE5NVuj
const SIP_TRUNK_ID = process.env.SIP_TRUNK_ID || 'ST_23t6SdE5NVuj';

@Injectable()
export class SipService {
  private readonly logger = new Logger(SipService.name);
  private readonly sipClient = new SipClient(LK_HOST, LK_API_KEY, LK_API_SECRET);

  /**
   * Dial an outbound phone number and bridge into a LiveKit room.
   */
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
          timeout: 30,
        },
      );
      this.logger.log(`[SIP] Call connected: ${JSON.stringify(result)}`);
      return { participantId: result?.participantIdentity || `sip-${phoneNumber}` };
    } catch (e) {
      this.logger.error(`[SIP] dialOutbound failed: ${(e as Error).message}`);
      throw e;
    }
  }

  /**
   * Check if SIP trunk is configured and ready.
   */
  isConfigured(): boolean {
    return !!SIP_TRUNK_ID;
  }
}
