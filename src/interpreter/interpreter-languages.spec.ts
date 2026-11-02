import {
  INTERPRETER_LANGUAGES,
  SIMULTANEOUS_SOURCES,
  SIMULTANEOUS_TARGETS,
  engineFor,
  isSupportedLang,
} from './interpreter-languages';

// The agent's own tables. They are outside jest's rootDir and outside dist/,
// which is why the backend keeps a copy — and this spec is that copy's check.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const agentNames = require('../../livekit-agent/lang-names.js') as {
  LANG_NAMES: Record<string, string>;
  SUPPORTED_LANGS: string[];
};
// eslint-disable-next-line @typescript-eslint/no-require-imports
const agentEngines = require('../../livekit-agent/interpreter-langs.js') as {
  SIMULTANEOUS_TARGETS: Set<string>;
  SIMULTANEOUS_SOURCES: Set<string>;
  chooseEngine: (sourceLang: string, targetLang: string) => string;
};

describe('interpreter languages: the copy matches the agent', () => {
  it('offers exactly the agent languages, in its order and with its names', () => {
    expect(INTERPRETER_LANGUAGES.map((l) => l.code)).toEqual(
      agentNames.SUPPORTED_LANGS,
    );
    expect(
      Object.fromEntries(INTERPRETER_LANGUAGES.map((l) => [l.code, l.name])),
    ).toEqual(agentNames.LANG_NAMES);
    expect(INTERPRETER_LANGUAGES).toHaveLength(81);
  });

  it('picks engines from the same two sets', () => {
    expect(SIMULTANEOUS_TARGETS).toEqual(agentEngines.SIMULTANEOUS_TARGETS);
    expect(SIMULTANEOUS_SOURCES).toEqual(agentEngines.SIMULTANEOUS_SOURCES);
  });

  it('chooses the agent engine for every pair a person can pick', () => {
    const mismatches: string[] = [];
    for (const { code: source } of INTERPRETER_LANGUAGES) {
      for (const { code: target } of INTERPRETER_LANGUAGES) {
        if (
          engineFor(source, target) !==
          agentEngines.chooseEngine(source, target)
        ) {
          mismatches.push(`${source}→${target}`);
        }
      }
    }
    expect(mismatches).toEqual([]);
  });
});

describe('isSupportedLang', () => {
  it('accepts a language the agent speaks', () => {
    expect(isSupportedLang('ru')).toBe(true);
    expect(isSupportedLang('zu')).toBe(true);
  });

  it('refuses regions, unknown codes, other cases and non-strings', () => {
    for (const code of ['pt-BR', 'xx', 'RU', '', 'dz', 42, null, undefined]) {
      expect(isSupportedLang(code)).toBe(false);
    }
  });
});

describe('engineFor', () => {
  it('is simultaneous when the model hears the speaker and speaks the listener language', () => {
    expect(engineFor('ru', 'de')).toBe('simultaneous');
    expect(engineFor('de', 'ru')).toBe('simultaneous');
  });

  it('falls back to phrases when the listener language is not a target', () => {
    expect(engineFor('ru', 'sk')).toBe('phrase');
  });

  it('falls back to phrases when the speaker language is not a source', () => {
    expect(engineFor('am', 'en')).toBe('phrase');
  });
});
