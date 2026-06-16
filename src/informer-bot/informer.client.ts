import { Injectable, Logger } from '@nestjs/common';
import { createHash, createHmac, randomUUID } from 'crypto';
import {
  assertEnvelope,
  OperatorRequiredCount,
  OperatorRequiredList,
  MiniAcquiringBalances,
  GatewaySystemWalletBalances,
  InformerAuthError,
  InformerNotConfiguredError,
  InformerNonceStoreError,
  InformerUnavailableError,
  InformerTimeoutError,
  InformerError,
} from './informer.types';

export interface InformerClientConfig {
  baseUrl: string;
  key: string;
  secret: string;
  timeoutMs?: number;
}

const EMPTY_BODY_SHA256 =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

@Injectable()
export class InformerClient {
  private readonly logger = new Logger(InformerClient.name);

  constructor(private readonly cfg: InformerClientConfig) {}

  buildSignature(
    method: string,
    requestUri: string,
    timestamp: string,
    body: string,
  ): string {
    const bodyHash =
      body === ''
        ? EMPTY_BODY_SHA256
        : createHash('sha256').update(body).digest('hex');
    const signingString = `${method}\n${requestUri}\n${timestamp}\n${bodyHash}`;
    return createHmac('sha256', this.cfg.secret)
      .update(signingString)
      .digest('hex');
  }

  mapStatusToError(status: number, body: string): InformerError {
    if (status === 401) return new InformerAuthError(body);
    if (status === 404) return new InformerNotConfiguredError(404, body);
    if (status === 503) {
      if (body.includes('nonce store unavailable'))
        return new InformerNonceStoreError(body);
      if (body.includes('not configured'))
        return new InformerNotConfiguredError(503, body);
      return new InformerUnavailableError(503, body);
    }
    return new InformerUnavailableError(status, body);
  }

  private async signedGet<T>(path: string): Promise<T> {
    const url = new URL(path, this.cfg.baseUrl);
    const requestUri = url.pathname + url.search;
    const ts = Math.floor(Date.now() / 1000).toString();
    const nonce = randomUUID().replace(/-/g, '');
    const signature = this.buildSignature('GET', requestUri, ts, '');

    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      this.cfg.timeoutMs ?? 25000,
    );

    let resp: Response;
    try {
      resp = await fetch(url.toString(), {
        method: 'GET',
        headers: {
          'X-Informer-Key': this.cfg.key,
          'X-Informer-Timestamp': ts,
          'X-Informer-Nonce': nonce,
          'X-Informer-Signature': signature,
        },
        signal: controller.signal,
      });
    } catch (e: any) {
      if (e?.name === 'AbortError') throw new InformerTimeoutError();
      throw new InformerUnavailableError(0, String(e?.message ?? e));
    } finally {
      clearTimeout(timer);
    }

    const text = await resp.text();
    if (resp.status === 200) {
      let json: unknown;
      try {
        json = JSON.parse(text);
      } catch {
        throw new InformerUnavailableError(
          200,
          `non-json: ${text.slice(0, 200)}`,
        );
      }
      const envelope = assertEnvelope<T>(json);
      return envelope.data;
    }
    throw this.mapStatusToError(resp.status, text);
  }

  getOperatorRequiredCount(): Promise<OperatorRequiredCount> {
    return this.signedGet<OperatorRequiredCount>(
      '/informer/v1/operator-required-wallets/count',
    );
  }

  getOperatorRequiredList(
    page = 1,
    perPage = 50,
  ): Promise<OperatorRequiredList> {
    const q = new URLSearchParams({
      page: String(page),
      per_page: String(perPage),
    }).toString();
    return this.signedGet<OperatorRequiredList>(
      `/informer/v1/operator-required-wallets?${q}`,
    );
  }

  getMiniAcquiringBalances(): Promise<MiniAcquiringBalances> {
    return this.signedGet<MiniAcquiringBalances>(
      '/informer/v1/mini-acquiring/balances',
    );
  }

  getGatewaySystemWalletBalances(): Promise<GatewaySystemWalletBalances> {
    return this.signedGet<GatewaySystemWalletBalances>(
      '/informer/v1/gateway/system-wallet-balances',
    );
  }
}
