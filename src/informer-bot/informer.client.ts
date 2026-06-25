import { Injectable, Logger } from '@nestjs/common';
import { createHash, createHmac, randomUUID } from 'crypto';
import {
  assertEnvelope,
  OperatorRequiredCount,
  OperatorRequiredList,
  OperatorWalletRetryResult,
  MiniAcquiringBalances,
  GatewaySystemWalletBalances,
  InformerAuthError,
  InformerBadRequestError,
  InformerNotConfiguredError,
  InformerNonceStoreError,
  InformerTotpError,
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
    if (status === 400) return new InformerBadRequestError(body);
    if (status === 401) return new InformerAuthError(body);
    if (status === 403) return new InformerTotpError(body);
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

  private buildAuthHeaders(
    method: string,
    requestUri: string,
    body: string,
  ): Record<string, string> {
    const ts = Math.floor(Date.now() / 1000).toString();
    const nonce = randomUUID().replace(/-/g, '');
    const signature = this.buildSignature(method, requestUri, ts, body);
    return {
      'X-Informer-Key': this.cfg.key,
      'X-Informer-Timestamp': ts,
      'X-Informer-Nonce': nonce,
      'X-Informer-Signature': signature,
    };
  }

  private async signedRequest<T>(
    method: 'GET' | 'POST',
    path: string,
    body: string,
  ): Promise<T> {
    const url = new URL(path, this.cfg.baseUrl);
    const requestUri = url.pathname + url.search;
    const headers = this.buildAuthHeaders(method, requestUri, body);
    if (method === 'POST') headers['Content-Type'] = 'application/json';

    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      this.cfg.timeoutMs ?? 25000,
    );

    let resp: Response;
    try {
      resp = await fetch(url.toString(), {
        method,
        headers,
        body: method === 'POST' ? body : undefined,
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

  private signedGet<T>(path: string): Promise<T> {
    return this.signedRequest<T>('GET', path, '');
  }

  private signedPost<T>(path: string, payload: unknown): Promise<T> {
    // Serialize once and pass the exact bytes to both sha256 (in signing
    // string) and fetch body. Any whitespace / key-order drift between the
    // two would yield 401 (signature mismatch).
    const body = JSON.stringify(payload);
    return this.signedRequest<T>('POST', path, body);
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

  retryOperatorWallet(
    walletId: number,
    totpCode: string,
  ): Promise<OperatorWalletRetryResult> {
    return this.signedPost<OperatorWalletRetryResult>(
      `/informer/v1/operator-required-wallets/${walletId}/retry`,
      { totp_code: totpCode },
    );
  }
}
