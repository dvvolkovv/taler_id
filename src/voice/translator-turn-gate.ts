// The assistant's translator mode (mode=translator) must answer every
// utterance with its translation and nothing else. Two inputs made it talk as
// itself instead; both are cut off here, on the server, so installed apps get
// the fix with a backend deploy.
//
//  - Text the app writes into the session. On every incoming chat message the
//    app injected "[СИСТЕМНОЕ УВЕДОМЛЕНИЕ] … сообщи пользователю" with a
//    response.create, and the translator replied in Russian ("Извините, я
//    здесь только для перевода…") — 2 of 2 in harness runs. A translator only
//    ever needs audio, session updates and tool results from the app.
//
//  - Turns without words. Server VAD now and then commits a cough, clatter or
//    the phone being put down; a reply is created for it and the model fills
//    it with "Я тебя не слышу" / "Yes, I'm here" — 17 of 17 such turns in
//    harness runs. So every reply is held until its utterance is transcribed
//    and dropped when the transcript has no words. The transcript arrives
//    ~0.35 s after the commit (gpt-4o-mini-transcribe, see
//    realtime-proxy-mode.ts), before the reply's audio is complete, and the
//    app plays a reply only once its audio is done — the hold costs no latency.
//    A transcript that is late or fails lets the reply through: losing a real
//    translation is worse than a stray remark.

// Whisper's transcript of noise; never a whole real utterance.
const NOISE_TRANSCRIPTS = new Set(['you']);

/** The fields of a Realtime event the gate looks at. */
export interface RealtimeEvent {
  type?: string;
  item_id?: string;
  transcript?: string;
  response_id?: string;
  response?: { id?: string };
  item?: { id?: string; type?: string };
  error?: { event_id?: string };
}

type Fields = Record<string, unknown>;
interface SessionShape {
  audio?: { input?: { transcription?: Fields } & Fields } & Fields;
}

export function hasWords(transcript: string | null | undefined): boolean {
  const text = (transcript ?? '')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .trim();
  return text.length > 0 && !NOISE_TRANSCRIPTS.has(text);
}

/** Client → OpenAI events a translator session accepts. */
export function translatorClientEventAllowed(ev: RealtimeEvent): boolean {
  if (ev?.type === 'response.create') return false;
  if (ev?.type === 'conversation.item.create' && ev.item?.type === 'message') {
    return false;
  }
  return true;
}

/** GA-shape session.update with the input transcription model replaced. */
export function withTranscriptionModel<
  T extends { type?: string; session?: unknown },
>(ev: T, model: string): T {
  if (ev?.type !== 'session.update') return ev;
  const session = ev.session as SessionShape | undefined;
  const input = session?.audio?.input;
  if (!session?.audio || !input?.transcription) return ev;
  return {
    ...ev,
    session: {
      ...session,
      audio: {
        ...session.audio,
        input: { ...input, transcription: { ...input.transcription, model } },
      },
    },
  };
}

export type TurnVerdict = 'words' | 'no_words' | 'timeout' | 'failed';

export interface TurnGateIo {
  toClient(data: string): void;
  toOpenAI(event: Record<string, unknown>): void;
  setTimer(fn: () => void, ms: number): void;
  onVerdict?(verdict: TurnVerdict): void;
}

interface Reply {
  id: string;
  itemId: string;
  state: 'hold' | 'pass' | 'drop';
  held: string[];
  outputItemIds: string[];
  done: boolean;
}

export class TranslatorTurnGate {
  private lastCommitted: string | undefined;
  /** Verdicts for transcripts that arrived before their reply. */
  private readonly early = new Map<string, boolean>();
  private readonly replies = new Map<string, Reply>();
  private readonly ownDeletes = new Set<string>();
  private readonly ownEventIds = new Set<string>();
  private seq = 0;

  constructor(
    private readonly io: TurnGateIo,
    private readonly opts: { holdMs: number } = { holdMs: 2000 },
  ) {}

  /** One OpenAI → client event; `data` is what would be forwarded as is. */
  fromOpenAI(ev: RealtimeEvent, data: string): void {
    switch (ev?.type) {
      case 'input_audio_buffer.committed':
        this.lastCommitted = ev.item_id;
        this.io.toClient(data);
        return;
      case 'response.created':
        this.onReplyCreated(ev.response?.id, data);
        return;
      case 'conversation.item.input_audio_transcription.completed':
        this.onTranscript(
          ev.item_id ?? '',
          hasWords(ev.transcript) ? 'words' : 'no_words',
          data,
        );
        return;
      case 'conversation.item.input_audio_transcription.failed':
        this.onTranscript(ev.item_id ?? '', 'failed', data);
        return;
      case 'conversation.item.deleted':
        if (!this.ownDeletes.delete(ev.item_id ?? '')) this.io.toClient(data);
        return;
      case 'error':
        if (!this.ownEventIds.delete(ev.error?.event_id ?? '')) {
          this.io.toClient(data);
        }
        return;
    }
    const reply = this.replies.get(ev?.response_id ?? ev?.response?.id ?? '');
    if (!reply) {
      this.io.toClient(data);
      return;
    }
    if (ev.type === 'response.output_item.added' && ev.item?.id) {
      reply.outputItemIds.push(ev.item.id);
    }
    if (reply.state === 'pass') this.io.toClient(data);
    else if (reply.state === 'hold') reply.held.push(data);
    if (ev.type === 'response.done') this.onReplyDone(reply);
  }

  private onReplyCreated(id: string | undefined, data: string): void {
    const itemId = this.lastCommitted;
    this.lastCommitted = undefined;
    if (!id || !itemId) {
      this.io.toClient(data);
      return;
    }
    const reply: Reply = {
      id,
      itemId,
      state: 'hold',
      held: [],
      outputItemIds: [],
      done: false,
    };
    this.replies.set(id, reply);
    const early = this.early.get(itemId);
    this.early.delete(itemId);
    if (early === true) {
      reply.state = 'pass';
      this.io.toClient(data);
    } else if (early === false) {
      this.drop(reply);
    } else {
      reply.held.push(data);
      this.io.setTimer(() => {
        if (reply.state !== 'hold') return;
        this.io.onVerdict?.('timeout');
        this.release(reply);
      }, this.opts.holdMs);
    }
  }

  private onTranscript(itemId: string, verdict: TurnVerdict, data: string) {
    this.io.onVerdict?.(verdict);
    const held = [...this.replies.values()].filter(
      (r) => r.itemId === itemId && r.state === 'hold',
    );
    if (verdict === 'no_words') {
      this.deleteItem(itemId);
      held.forEach((r) => this.drop(r));
      if (!held.length) this.remember(itemId, false);
      return; // the empty transcript is not news for the phone
    }
    held.forEach((r) => this.release(r));
    if (!held.length) this.remember(itemId, true);
    this.io.toClient(data);
  }

  private onReplyDone(reply: Reply): void {
    reply.done = true;
    if (reply.state === 'drop') this.deleteOutputs(reply);
    // A held reply waits for its verdict (or the timer).
    if (reply.state !== 'hold') this.replies.delete(reply.id);
  }

  private release(reply: Reply): void {
    reply.state = 'pass';
    reply.held.forEach((d) => this.io.toClient(d));
    reply.held = [];
    if (reply.done) this.replies.delete(reply.id);
  }

  private drop(reply: Reply): void {
    reply.state = 'drop';
    reply.held = [];
    if (reply.done) {
      this.deleteOutputs(reply);
      this.replies.delete(reply.id);
    } else {
      this.send({ type: 'response.cancel', response_id: reply.id });
    }
  }

  private deleteOutputs(reply: Reply): void {
    reply.outputItemIds.forEach((id) => this.deleteItem(id));
    reply.outputItemIds = [];
  }

  // Keeps the conversation free of noise turns and of the remarks the model
  // made about them, so later replies cannot pick the pattern up.
  private deleteItem(itemId: string): void {
    this.ownDeletes.add(itemId);
    this.send({ type: 'conversation.item.delete', item_id: itemId });
  }

  private send(event: Record<string, unknown>): void {
    const eventId = `tgate_${++this.seq}`;
    this.ownEventIds.add(eventId);
    this.io.toOpenAI({ ...event, event_id: eventId });
  }

  private remember(itemId: string, words: boolean): void {
    this.early.set(itemId, words);
    // Transcripts of turns that never get a reply would otherwise pile up.
    if (this.early.size > 32) {
      this.early.delete(this.early.keys().next().value as string);
    }
  }
}
