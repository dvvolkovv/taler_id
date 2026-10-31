// Languages the agent's translators know, by ISO 639-1 code. Moved out of
// translator.js unchanged so the face-to-face interpreter shares them.

// All languages supported by Whisper + GPT Realtime for translation
const LANG_NAMES = {
  af: 'Afrikaans', am: 'Amharic', ar: 'Arabic', az: 'Azerbaijani',
  be: 'Belarusian', bg: 'Bulgarian', bn: 'Bengali', bs: 'Bosnian',
  ca: 'Catalan', cs: 'Czech', cy: 'Welsh', da: 'Danish',
  de: 'German', el: 'Greek', en: 'English', es: 'Spanish',
  et: 'Estonian', eu: 'Basque', fa: 'Persian', fi: 'Finnish',
  fr: 'French', ga: 'Irish', gl: 'Galician', gu: 'Gujarati',
  ha: 'Hausa', he: 'Hebrew', hi: 'Hindi', hr: 'Croatian',
  hu: 'Hungarian', hy: 'Armenian', id: 'Indonesian', is: 'Icelandic',
  it: 'Italian', ja: 'Japanese', jv: 'Javanese', ka: 'Georgian',
  kk: 'Kazakh', km: 'Khmer', kn: 'Kannada', ko: 'Korean',
  lo: 'Lao', lt: 'Lithuanian', lv: 'Latvian', mk: 'Macedonian',
  ml: 'Malayalam', mn: 'Mongolian', mr: 'Marathi', ms: 'Malay',
  mt: 'Maltese', my: 'Myanmar', ne: 'Nepali', nl: 'Dutch',
  no: 'Norwegian', pa: 'Punjabi', pl: 'Polish', ps: 'Pashto',
  pt: 'Portuguese', ro: 'Romanian', ru: 'Russian', si: 'Sinhala',
  sk: 'Slovak', sl: 'Slovenian', so: 'Somali', sq: 'Albanian',
  sr: 'Serbian', su: 'Sundanese', sv: 'Swedish', sw: 'Swahili',
  ta: 'Tamil', te: 'Telugu', tg: 'Tajik', th: 'Thai',
  tl: 'Filipino', tr: 'Turkish', uk: 'Ukrainian', ur: 'Urdu',
  uz: 'Uzbek', vi: 'Vietnamese', yo: 'Yoruba', zh: 'Chinese',
  zu: 'Zulu',
};
const SUPPORTED_LANGS = Object.keys(LANG_NAMES);
const LANG_VOICES = { ru: 'alloy', en: 'echo', de: 'ash', it: 'coral', es: 'sage', zh: 'alloy', ar: 'shimmer', ja: 'ballad' };

module.exports = { LANG_NAMES, SUPPORTED_LANGS, LANG_VOICES };
