export type ToolKind = 'search' | 'file' | 'cmd' | 'image' | 'other';

export interface ToolLabel {
  kind: ToolKind;
  emoji: string;
  ru: string;
  en: string;
}

export const TOOL_LABELS: Record<string, ToolLabel> = {
  WebSearch: { kind: 'search', emoji: '🔍', ru: 'Ищу в интернете…',    en: 'Searching the web…' },
  WebFetch:  { kind: 'search', emoji: '🌐', ru: 'Открываю страницу…',  en: 'Fetching page…' },
  Read:      { kind: 'file',   emoji: '📄', ru: 'Читаю файл…',         en: 'Reading file…' },
  Write:     { kind: 'file',   emoji: '📝', ru: 'Записываю файл…',     en: 'Writing file…' },
  Edit:      { kind: 'file',   emoji: '✏️', ru: 'Редактирую файл…',    en: 'Editing file…' },
  Glob:      { kind: 'file',   emoji: '🗂️', ru: 'Ищу файлы…',          en: 'Listing files…' },
  Grep:      { kind: 'file',   emoji: '🔎', ru: 'Ищу по содержимому…', en: 'Searching contents…' },
  Bash:      { kind: 'cmd',    emoji: '💻', ru: 'Выполняю команду…',   en: 'Running command…' },
};

export const PHASE_LABELS = {
  thinking:  { emoji: '🤔', ru: 'Думаю…',         en: 'Thinking…' },
  preparing: { emoji: '✍️', ru: 'Готовлю ответ…', en: 'Preparing answer…' },
  error:     { emoji: '❌', ru: 'Ошибка',         en: 'Error' },
};

export const UNKNOWN_TOOL_LABEL: ToolLabel = {
  kind: 'other', emoji: '⚙️', ru: 'Работаю…', en: 'Working…',
};

export function refineBashLabel(input: string): ToolLabel | null {
  if (/generate_image\.sh/.test(input)) {
    return { kind: 'image', emoji: '🎨', ru: 'Генерирую картинку…', en: 'Generating image…' };
  }
  return null;
}

export function resolveToolLabel(toolName: string, input: string): ToolLabel {
  if (toolName === 'Bash') {
    const refined = refineBashLabel(input);
    if (refined) return refined;
  }
  return TOOL_LABELS[toolName] ?? UNKNOWN_TOOL_LABEL;
}
