import * as fs from 'fs';
import * as path from 'path';
import {
  upgradeLegacyTranslatorPrompt,
  withUpgradedTranslatorPrompt,
} from './translator-legacy-prompt';

// Prompts produced by the app's own translator_prompt.dart: `old` as shipped up
// to 1.1.37 (mobile beb8233), `new` with rule 5 and the ANY-language note
// (mobile be6076b).
interface Fixture {
  owner: string;
  target: string | null;
  old: string;
  new: string;
}
const fixtures = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, 'translator-legacy-prompt.fixtures.json'),
    'utf8',
  ),
) as Fixture[];

describe('upgradeLegacyTranslatorPrompt', () => {
  it.each(fixtures.map((f) => [`${f.owner}→${f.target ?? 'not chosen'}`, f]))(
    'turns the 1.1.37 prompt into the current one byte for byte (%s)',
    (_, f) => {
      expect(upgradeLegacyTranslatorPrompt(f.old)).toBe(f.new);
    },
  );

  it('leaves the current prompt alone', () => {
    for (const f of fixtures) {
      expect(upgradeLegacyTranslatorPrompt(f.new)).toBe(f.new);
    }
  });

  it('leaves other instructions alone', () => {
    const assistant = 'Ты — голосовой ассистент Taler ID. Отвечай коротко.';
    expect(upgradeLegacyTranslatorPrompt(assistant)).toBe(assistant);
  });

  it('does nothing to a prompt it only partly recognises', () => {
    const edited = fixtures[0].old.replace(
      'Keep names, numbers, places exact.',
      'Keep names exact.',
    );
    expect(upgradeLegacyTranslatorPrompt(edited)).toBe(edited);
  });
});

describe('withUpgradedTranslatorPrompt', () => {
  it('upgrades the instructions of a session.update and keeps the rest', () => {
    const f = fixtures[0];
    const ev = {
      type: 'session.update',
      session: { type: 'realtime', instructions: f.old, tools: [] },
    };
    const out = withUpgradedTranslatorPrompt(ev);
    expect(out.session.instructions).toBe(f.new);
    expect(out.session.tools).toEqual([]);
    expect(ev.session.instructions).toBe(f.old);
  });

  it('passes other events through untouched', () => {
    const audio = { type: 'input_audio_buffer.append', audio: 'AA' };
    expect(withUpgradedTranslatorPrompt(audio)).toBe(audio);
    const partial = { type: 'session.update', session: { type: 'realtime' } };
    expect(withUpgradedTranslatorPrompt(partial)).toBe(partial);
    const current = {
      type: 'session.update',
      session: { instructions: fixtures[0].new },
    };
    expect(withUpgradedTranslatorPrompt(current)).toBe(current);
  });
});
