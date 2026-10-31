import { DEFAULT_TRANSLATOR_TRANSCRIBE_MODEL } from './realtime-proxy-mode';
import {
  TranslatorTurnGate,
  hasWords,
  translatorClientEventAllowed,
  withTranscriptionModel,
} from './translator-turn-gate';

function setup() {
  const toClient: string[] = [];
  const toOpenAI: any[] = [];
  const timers: Array<() => void> = [];
  const verdicts: string[] = [];
  const gate = new TranslatorTurnGate(
    {
      toClient: (d) => toClient.push(d),
      toOpenAI: (e) => toOpenAI.push(e),
      setTimer: (fn) => {
        timers.push(fn);
      },
      onVerdict: (v) => verdicts.push(v),
    },
    { holdMs: 2000 },
  );
  const server = (ev: any) => gate.fromOpenAI(ev, JSON.stringify(ev));
  const sent = () => toClient.map((d) => JSON.parse(d).type);
  const sentTo = (type: string) => toOpenAI.filter((e) => e.type === type);
  return { server, toClient, toOpenAI, timers, verdicts, sent, sentTo };
}

const committed = (item: string) => ({
  type: 'input_audio_buffer.committed',
  item_id: item,
});
const created = (resp: string) => ({
  type: 'response.created',
  response: { id: resp },
});
const itemAdded = (resp: string, item: string) => ({
  type: 'response.output_item.added',
  response_id: resp,
  item: { id: item, type: 'message', role: 'assistant' },
});
const delta = (resp: string, item: string) => ({
  type: 'response.audio.delta',
  response_id: resp,
  item_id: item,
  delta: 'AAAA',
});
const done = (resp: string, status = 'completed') => ({
  type: 'response.done',
  response: { id: resp, status },
});
const transcript = (item: string, text: string) => ({
  type: 'conversation.item.input_audio_transcription.completed',
  item_id: item,
  transcript: text,
});

describe('TranslatorTurnGate', () => {
  it('holds a reply until its utterance is transcribed, then releases it in order', () => {
    const g = setup();
    g.server(committed('u1'));
    g.server(created('r1'));
    g.server(itemAdded('r1', 'a1'));
    g.server(delta('r1', 'a1'));
    expect(g.sent()).toEqual(['input_audio_buffer.committed']);

    g.server(transcript('u1', 'Привет, как дела?'));
    expect(g.sent()).toEqual([
      'input_audio_buffer.committed',
      'response.created',
      'response.output_item.added',
      'response.audio.delta',
      'conversation.item.input_audio_transcription.completed',
    ]);

    g.server(done('r1'));
    expect(g.sent().at(-1)).toBe('response.done');
    expect(g.toOpenAI).toEqual([]);
    expect(g.verdicts).toEqual(['words']);
  });

  it('drops the reply to an utterance without words and removes both from the conversation', () => {
    const g = setup();
    g.server(committed('u1'));
    g.server(created('r1'));
    g.server(itemAdded('r1', 'a1'));
    g.server(delta('r1', 'a1'));
    g.server(transcript('u1', ''));
    g.server(delta('r1', 'a1'));
    g.server(done('r1', 'cancelled'));

    // Nothing of the reply, nor the empty transcript, reaches the phone.
    expect(g.sent()).toEqual(['input_audio_buffer.committed']);
    expect(g.sentTo('response.cancel')).toEqual([
      expect.objectContaining({ response_id: 'r1' }),
    ]);
    expect(g.sentTo('conversation.item.delete').map((e) => e.item_id)).toEqual([
      'u1',
      'a1',
    ]);
    expect(g.verdicts).toEqual(['no_words']);
  });

  it('swallows the deletions it caused and the errors of its own requests', () => {
    const g = setup();
    g.server(committed('u1'));
    g.server(created('r1'));
    g.server(itemAdded('r1', 'a1'));
    g.server(transcript('u1', ''));
    g.server(done('r1', 'cancelled'));
    const cancel = g.sentTo('response.cancel')[0];

    g.server({ type: 'conversation.item.deleted', item_id: 'u1' });
    g.server({ type: 'conversation.item.deleted', item_id: 'a1' });
    g.server({
      type: 'error',
      error: { code: 'response_cancel_not_active', event_id: cancel.event_id },
    });
    expect(g.sent()).toEqual(['input_audio_buffer.committed']);

    // Someone else's deletions and errors still go through.
    g.server({ type: 'conversation.item.deleted', item_id: 'other' });
    g.server({ type: 'error', error: { code: 'x', event_id: 'client_1' } });
    expect(g.sent().slice(1)).toEqual(['conversation.item.deleted', 'error']);
  });

  it('transcript ahead of the reply: a reply with words passes straight through', () => {
    const g = setup();
    g.server(committed('u1'));
    g.server(transcript('u1', 'Hello'));
    g.server(created('r1'));
    g.server(delta('r1', 'a1'));
    expect(g.sent()).toEqual([
      'input_audio_buffer.committed',
      'conversation.item.input_audio_transcription.completed',
      'response.created',
      'response.audio.delta',
    ]);
    expect(g.timers).toHaveLength(0);
  });

  it('transcript ahead of the reply: no words means the reply never reaches the phone', () => {
    const g = setup();
    g.server(committed('u1'));
    g.server(transcript('u1', '   '));
    g.server(created('r1'));
    g.server(itemAdded('r1', 'a1'));
    g.server(delta('r1', 'a1'));
    g.server(done('r1', 'cancelled'));
    expect(g.sent()).toEqual(['input_audio_buffer.committed']);
    expect(g.sentTo('response.cancel')).toHaveLength(1);
    expect(g.sentTo('conversation.item.delete').map((e) => e.item_id)).toEqual([
      'u1',
      'a1',
    ]);
  });

  it('a reply finished before the transcript is released whole', () => {
    const g = setup();
    g.server(committed('u1'));
    g.server(created('r1'));
    g.server(delta('r1', 'a1'));
    g.server(done('r1'));
    expect(g.sent()).toEqual(['input_audio_buffer.committed']);
    g.server(transcript('u1', 'Да.'));
    expect(g.sent()).toEqual([
      'input_audio_buffer.committed',
      'response.created',
      'response.audio.delta',
      'response.done',
      'conversation.item.input_audio_transcription.completed',
    ]);
  });

  it('a finished reply to noise is not cancelled, only removed', () => {
    const g = setup();
    g.server(committed('u1'));
    g.server(created('r1'));
    g.server(itemAdded('r1', 'a1'));
    g.server(done('r1'));
    g.server(transcript('u1', ''));
    expect(g.sent()).toEqual(['input_audio_buffer.committed']);
    expect(g.sentTo('response.cancel')).toEqual([]);
    expect(g.sentTo('conversation.item.delete').map((e) => e.item_id)).toEqual([
      'u1',
      'a1',
    ]);
  });

  it('lets the reply through when the transcript does not come in time', () => {
    const g = setup();
    g.server(committed('u1'));
    g.server(created('r1'));
    g.server(delta('r1', 'a1'));
    expect(g.timers).toHaveLength(1);
    g.timers[0]();
    expect(g.sent()).toEqual([
      'input_audio_buffer.committed',
      'response.created',
      'response.audio.delta',
    ]);
    g.server(done('r1'));
    expect(g.sent().at(-1)).toBe('response.done');
    expect(g.verdicts).toEqual(['timeout']);

    // A transcript that turns up later changes nothing.
    g.server(transcript('u1', ''));
    expect(g.sentTo('response.cancel')).toEqual([]);
  });

  it('lets the reply through when transcription fails', () => {
    const g = setup();
    g.server(committed('u1'));
    g.server(created('r1'));
    g.server(delta('r1', 'a1'));
    g.server({
      type: 'conversation.item.input_audio_transcription.failed',
      item_id: 'u1',
      error: { message: 'x' },
    });
    expect(g.sent()).toEqual([
      'input_audio_buffer.committed',
      'response.created',
      'response.audio.delta',
      'conversation.item.input_audio_transcription.failed',
    ]);
    expect(g.verdicts).toEqual(['failed']);
  });

  it('events that are not part of a reply are never held', () => {
    const g = setup();
    g.server(committed('u1'));
    g.server(created('r1'));
    g.server({ type: 'input_audio_buffer.speech_started' });
    g.server({ type: 'rate_limits.updated' });
    g.server({ type: 'session.updated', session: {} });
    expect(g.sent()).toEqual([
      'input_audio_buffer.committed',
      'input_audio_buffer.speech_started',
      'rate_limits.updated',
      'session.updated',
    ]);
  });

  it('a reply that follows no utterance is not held', () => {
    const g = setup();
    g.server(created('r9'));
    g.server(delta('r9', 'a9'));
    expect(g.sent()).toEqual(['response.created', 'response.audio.delta']);
  });

  it('each utterance gets its own verdict', () => {
    const g = setup();
    g.server(committed('u1'));
    g.server(created('r1'));
    g.server(delta('r1', 'a1'));
    g.server(transcript('u1', ''));
    g.server(done('r1', 'cancelled'));
    g.server(committed('u2'));
    g.server(created('r2'));
    g.server(delta('r2', 'a2'));
    g.server(transcript('u2', 'Где вокзал?'));
    expect(g.sent()).toEqual([
      'input_audio_buffer.committed',
      'input_audio_buffer.committed',
      'response.created',
      'response.audio.delta',
      'conversation.item.input_audio_transcription.completed',
    ]);
  });
});

describe('hasWords', () => {
  it.each(['', '   ', '…', '. . .', 'you', 'You.'])('%j has no words', (t) => {
    expect(hasWords(t)).toBe(false);
  });

  it.each(['Да.', 'Ok', '10', 'Thank you.', 'Ты здесь?'])(
    '%j has words',
    (t) => {
      expect(hasWords(t)).toBe(true);
    },
  );

  it('a missing transcript has no words', () => {
    expect(hasWords(undefined)).toBe(false);
  });
});

describe('translatorClientEventAllowed', () => {
  it('blocks text the app injects and its requests for a reply', () => {
    expect(translatorClientEventAllowed({ type: 'response.create' })).toBe(
      false,
    );
    expect(
      translatorClientEventAllowed({
        type: 'conversation.item.create',
        item: {
          type: 'message',
          role: 'user',
          content: [{ type: 'input_text', text: '[СИСТЕМНОЕ УВЕДОМЛЕНИЕ] …' }],
        },
      }),
    ).toBe(false);
  });

  it('lets through audio, session updates and tool results', () => {
    expect(
      translatorClientEventAllowed({
        type: 'input_audio_buffer.append',
        audio: 'AA',
      }),
    ).toBe(true);
    expect(
      translatorClientEventAllowed({ type: 'session.update', session: {} }),
    ).toBe(true);
    expect(
      translatorClientEventAllowed({
        type: 'conversation.item.create',
        item: { type: 'function_call_output', call_id: 'c1', output: '{}' },
      }),
    ).toBe(true);
  });
});

describe('withTranscriptionModel', () => {
  it('replaces the transcription model and keeps the rest', () => {
    const ev = {
      type: 'session.update',
      session: {
        type: 'realtime',
        instructions: 'x',
        audio: {
          input: {
            transcription: { model: 'whisper-1', prompt: 'p' },
            turn_detection: { type: 'server_vad' },
          },
        },
      },
    };
    const out = withTranscriptionModel(ev, DEFAULT_TRANSLATOR_TRANSCRIBE_MODEL);
    expect(out.session.audio.input.transcription).toEqual({
      model: 'gpt-4o-mini-transcribe',
      prompt: 'p',
    });
    expect(out.session.audio.input.turn_detection).toEqual({
      type: 'server_vad',
    });
    expect(out.session.instructions).toBe('x');
    expect(ev.session.audio.input.transcription.model).toBe('whisper-1');
  });

  it('leaves events without a transcription setting alone', () => {
    const partial = {
      type: 'session.update',
      session: { type: 'realtime', instructions: 'y' },
    };
    expect(withTranscriptionModel(partial, 'm')).toBe(partial);
    const other = { type: 'response.create' };
    expect(withTranscriptionModel(other, 'm')).toBe(other);
  });
});
