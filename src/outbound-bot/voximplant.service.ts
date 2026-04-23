import { Injectable, Logger } from '@nestjs/common';

const VOX_API_URL = 'https://api.voximplant.com/platform_api';
const VOX_ACCOUNT_ID = process.env.VOX_ACCOUNT_ID || '';
const VOX_API_KEY = process.env.VOX_API_KEY || '';
const VOX_APPLICATION_ID = process.env.VOX_APPLICATION_ID || '';
const VOX_RULE_ID = process.env.VOX_RULE_ID || '';
const VOX_CALLER_ID = process.env.VOX_CALLER_ID || '';
const VOX_VOICE_TURN_URL = process.env.VOX_VOICE_TURN_URL || 'https://staging.id.taler.tirol/voice-turn';

export interface VoximplantCallParams {
  phone: string;
  sessionId: string;
  metadata: Record<string, any>;
}

export interface VoximplantCallResult {
  callSessionHistoryId: number;
}

@Injectable()
export class VoximplantService {
  private readonly logger = new Logger(VoximplantService.name);

  isConfigured(): boolean {
    return !!(VOX_ACCOUNT_ID && VOX_API_KEY && VOX_APPLICATION_ID && VOX_RULE_ID);
  }

  async startOutboundCall(params: VoximplantCallParams): Promise<VoximplantCallResult> {
    if (!this.isConfigured()) {
      throw new Error('Voximplant not configured');
    }

    const body = new URLSearchParams({
      account_id: VOX_ACCOUNT_ID,
      api_key: VOX_API_KEY,
      application_id: VOX_APPLICATION_ID,
      rule_id: VOX_RULE_ID,
      script_custom_data: JSON.stringify({
        phone: params.phone,
        callerID: VOX_CALLER_ID,
        sessionId: params.sessionId,
        voiceTurnUrl: VOX_VOICE_TURN_URL,
        metadata: params.metadata,
      }),
    });

    this.logger.log(`[Vox] startOutboundCall phone=${params.phone} session=${params.sessionId}`);
    const resp = await fetch(`${VOX_API_URL}/StartScenarios/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    const data: any = await resp.json();
    if (data.result !== 1) {
      this.logger.error(`[Vox] StartScenarios failed: ${JSON.stringify(data)}`);
      throw new Error(data.error?.msg || 'StartScenarios failed');
    }
    return { callSessionHistoryId: data.call_session_history_id };
  }

  /** Get recording URL for a completed call session. */
  async getCallRecording(callSessionHistoryId: number): Promise<string | null> {
    if (!this.isConfigured()) return null;
    const body = new URLSearchParams({
      account_id: VOX_ACCOUNT_ID,
      api_key: VOX_API_KEY,
      call_session_history_id: callSessionHistoryId.toString(),
      with_records: 'true',
    });
    try {
      const resp = await fetch(`${VOX_API_URL}/GetCallHistory/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      });
      const data: any = await resp.json();
      const session = data?.result?.[0];
      const records = session?.records || [];
      return records[0]?.record_url || null;
    } catch (e) {
      this.logger.warn(`[Vox] GetCallHistory failed: ${(e as Error).message}`);
      return null;
    }
  }
}
