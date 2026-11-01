/**
 * Languages of the face-to-face interpreter, by ISO 639-1 code, and which
 * engine renders each pair.
 *
 * A copy of the agent's tables (livekit-agent/lang-names.js and
 * livekit-agent/interpreter-langs.js): the build does not put livekit-agent/
 * into dist/, so the backend cannot require them at run time.
 * interpreter-languages.spec.ts compares the copy with the originals. A code
 * the backend accepts and the agent refuses would only surface after the
 * host's billing had opened, as a 503 to the guest.
 */

export const INTERPRETER_LANGUAGES: ReadonlyArray<{
  code: string;
  name: string;
}> = [
  { code: 'af', name: 'Afrikaans' },
  { code: 'am', name: 'Amharic' },
  { code: 'ar', name: 'Arabic' },
  { code: 'az', name: 'Azerbaijani' },
  { code: 'be', name: 'Belarusian' },
  { code: 'bg', name: 'Bulgarian' },
  { code: 'bn', name: 'Bengali' },
  { code: 'bs', name: 'Bosnian' },
  { code: 'ca', name: 'Catalan' },
  { code: 'cs', name: 'Czech' },
  { code: 'cy', name: 'Welsh' },
  { code: 'da', name: 'Danish' },
  { code: 'de', name: 'German' },
  { code: 'el', name: 'Greek' },
  { code: 'en', name: 'English' },
  { code: 'es', name: 'Spanish' },
  { code: 'et', name: 'Estonian' },
  { code: 'eu', name: 'Basque' },
  { code: 'fa', name: 'Persian' },
  { code: 'fi', name: 'Finnish' },
  { code: 'fr', name: 'French' },
  { code: 'ga', name: 'Irish' },
  { code: 'gl', name: 'Galician' },
  { code: 'gu', name: 'Gujarati' },
  { code: 'ha', name: 'Hausa' },
  { code: 'he', name: 'Hebrew' },
  { code: 'hi', name: 'Hindi' },
  { code: 'hr', name: 'Croatian' },
  { code: 'hu', name: 'Hungarian' },
  { code: 'hy', name: 'Armenian' },
  { code: 'id', name: 'Indonesian' },
  { code: 'is', name: 'Icelandic' },
  { code: 'it', name: 'Italian' },
  { code: 'ja', name: 'Japanese' },
  { code: 'jv', name: 'Javanese' },
  { code: 'ka', name: 'Georgian' },
  { code: 'kk', name: 'Kazakh' },
  { code: 'km', name: 'Khmer' },
  { code: 'kn', name: 'Kannada' },
  { code: 'ko', name: 'Korean' },
  { code: 'lo', name: 'Lao' },
  { code: 'lt', name: 'Lithuanian' },
  { code: 'lv', name: 'Latvian' },
  { code: 'mk', name: 'Macedonian' },
  { code: 'ml', name: 'Malayalam' },
  { code: 'mn', name: 'Mongolian' },
  { code: 'mr', name: 'Marathi' },
  { code: 'ms', name: 'Malay' },
  { code: 'mt', name: 'Maltese' },
  { code: 'my', name: 'Myanmar' },
  { code: 'ne', name: 'Nepali' },
  { code: 'nl', name: 'Dutch' },
  { code: 'no', name: 'Norwegian' },
  { code: 'pa', name: 'Punjabi' },
  { code: 'pl', name: 'Polish' },
  { code: 'ps', name: 'Pashto' },
  { code: 'pt', name: 'Portuguese' },
  { code: 'ro', name: 'Romanian' },
  { code: 'ru', name: 'Russian' },
  { code: 'si', name: 'Sinhala' },
  { code: 'sk', name: 'Slovak' },
  { code: 'sl', name: 'Slovenian' },
  { code: 'so', name: 'Somali' },
  { code: 'sq', name: 'Albanian' },
  { code: 'sr', name: 'Serbian' },
  { code: 'su', name: 'Sundanese' },
  { code: 'sv', name: 'Swedish' },
  { code: 'sw', name: 'Swahili' },
  { code: 'ta', name: 'Tamil' },
  { code: 'te', name: 'Telugu' },
  { code: 'tg', name: 'Tajik' },
  { code: 'th', name: 'Thai' },
  { code: 'tl', name: 'Filipino' },
  { code: 'tr', name: 'Turkish' },
  { code: 'uk', name: 'Ukrainian' },
  { code: 'ur', name: 'Urdu' },
  { code: 'uz', name: 'Uzbek' },
  { code: 'vi', name: 'Vietnamese' },
  { code: 'yo', name: 'Yoruba' },
  { code: 'zh', name: 'Chinese' },
  { code: 'zu', name: 'Zulu' },
];

const CODES: ReadonlySet<string> = new Set(
  INTERPRETER_LANGUAGES.map((l) => l.code),
);

export function isSupportedLang(code: unknown): code is string {
  return typeof code === 'string' && CODES.has(code);
}

export type EngineKind = 'simultaneous' | 'phrase';

/** Languages gpt-realtime-translate speaks: the listener's side of a pair. */
export const SIMULTANEOUS_TARGETS: ReadonlySet<string> = new Set(
  'en es pt fr ja ru zh de ko hi id vi it'.split(' '),
);

/**
 * Languages gpt-realtime-translate hears: the speaker's side of a pair. Wider
 * than INTERPRETER_LANGUAGES, as copied from OpenAI's list.
 */
export const SIMULTANEOUS_SOURCES: ReadonlySet<string> = new Set(
  (
    'af ar az be bg bn bs ca cs cy da de dz el en eo es et eu fa fi fr gl gu ' +
    'he hi hr ht hu hy id it ja jv ka kk ko ku la lt lv mi mk ml mn ms my ne ' +
    'nl nn no pa pl pt ro ru sk sl sn sq sr sv sw te th tl tr uk uz vi yo zh'
  ).split(' '),
);

/**
 * How speech in sourceLang reaches a listener in targetLang: simultaneously,
 * or phrase by phrase on the full realtime model when the translate model
 * cannot do the pair. Tells each side what to expect before the agent starts.
 */
export function engineFor(sourceLang: string, targetLang: string): EngineKind {
  return SIMULTANEOUS_TARGETS.has(targetLang) &&
    SIMULTANEOUS_SOURCES.has(sourceLang)
    ? 'simultaneous'
    : 'phrase';
}
