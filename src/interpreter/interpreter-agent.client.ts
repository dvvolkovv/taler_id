import { Injectable, Logger } from '@nestjs/common';

export interface AgentParticipant {
  userId: string;
  lang: string;
  embedding: number[];
}

export interface AgentStartBody {
  sessionId: string;
  roomName: string;
  participants: [AgentParticipant, AgentParticipant];
}

/**
 * The agent could not be reached or refused. Carries no part of the request
 * on purpose: a start request holds both people's voice prints.
 */
export class AgentCallError extends Error {
  constructor(
    /** The agent's HTTP status, 0 when there was no answer. */
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'AgentCallError';
  }
}

const DEFAULT_AGENT_URL = 'http://localhost:3100';
// The agent bounds its LiveKit connect at 15 s and then publishes two tracks;
// a start answered after we gave up would leave it running unasked.
const START_TIMEOUT_MS = 35_000;
const STOP_TIMEOUT_MS = 10_000;
// The selftest opens both engines' OpenAI sessions in parallel, 10 s each at most.
const SELFTEST_TIMEOUT_MS = 25_000;

/**
 * The backend's side of the agent's interpreter routes
 * (livekit-agent/interpreter-routes.js). Every call carries
 * INTERPRETER_SHARED_SECRET and has its own timeout: unlike the older agent
 * calls, these sit on a person's request or on the reconciler's tick.
 */
@Injectable()
export class InterpreterAgentClient {
  private readonly log = new Logger(InterpreterAgentClient.name);

  /** The HTTP call itself; specs replace it. */
  fetchFn: typeof fetch = (input, init) => fetch(input, init);

  /** Resolves once the agent is in the room; any other outcome throws AgentCallError. */
  async start(body: AgentStartBody): Promise<void> {
    const res = await this.call(
      'POST',
      '/interpreter/start',
      START_TIMEOUT_MS,
      body,
    );
    discardBody(res);
    if (!res.ok) {
      throw new AgentCallError(
        res.status,
        `agent refused start: ${res.status}`,
      );
    }
  }

  /** Best effort: the session is closing either way, so failures are only logged. */
  async stop(roomName: string): Promise<void> {
    const body = { roomName };
    try {
      const res = await this.call(
        'POST',
        '/interpreter/stop',
        STOP_TIMEOUT_MS,
        body,
      );
      discardBody(res);
      if (!res.ok) {
        this.log.warn(`stop for ${roomName}: agent answered ${res.status}`);
      }
    } catch (e) {
      this.log.warn(`stop for ${roomName} failed: ${errorText(e)}`);
    }
  }

  /** The agent's own answer and status; 503 when there was none. */
  async selftest(): Promise<{ status: number; body: unknown }> {
    let status = 0;
    try {
      const res = await this.call(
        'GET',
        '/interpreter/selftest',
        SELFTEST_TIMEOUT_MS,
      );
      status = res.status;
      return { status, body: await res.json() };
    } catch (e) {
      // An answer that is not JSON came from a proxy in front of the agent
      // (nginx's 502 page): its status says more than the parser's error.
      const reason = status
        ? `agent answered ${status}, not JSON`
        : errorText(e);
      return { status: 503, body: { ok: false, reason } };
    }
  }

  /** Returns any answer as is; throws AgentCallError(0) when there is none. */
  private async call(
    method: 'GET' | 'POST',
    path: string,
    timeoutMs: number,
    body?: object,
  ): Promise<Response> {
    const secret = process.env.INTERPRETER_SHARED_SECRET;
    // The agent would refuse anyway, but a start must not carry voice prints
    // out of the backend on a request that cannot be authorised.
    if (!secret) {
      throw new AgentCallError(0, 'INTERPRETER_SHARED_SECRET is not set');
    }
    const base = (process.env.AI_AGENT_URL || DEFAULT_AGENT_URL).replace(
      /\/+$/,
      '',
    );
    try {
      return await this.fetchFn(base + path, {
        method,
        headers: {
          ...(body ? { 'Content-Type': 'application/json' } : {}),
          'x-interpreter-secret': secret,
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      throw new AgentCallError(0, `agent unreachable: ${errorText(e)}`);
    }
  }
}

/** fetch resolves on the headers; an unread body would keep the socket busy. */
function discardBody(res: Response): void {
  void res.body?.cancel().catch(() => undefined);
}

/** Why a call failed: fetch names the cause (refused, timed out), never the request. */
function errorText(e: unknown): string {
  if (!(e instanceof Error)) return String(e);
  const code = (e.cause as { code?: unknown } | undefined)?.code;
  return typeof code === 'string' ? `${e.message} (${code})` : e.message;
}
