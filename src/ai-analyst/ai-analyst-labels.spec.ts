import {
  TOOL_LABELS,
  PHASE_LABELS,
  UNKNOWN_TOOL_LABEL,
  refineBashLabel,
  resolveToolLabel,
  ToolKind,
} from './ai-analyst-labels';

describe('ai-analyst-labels', () => {
  describe('TOOL_LABELS', () => {
    it('maps WebSearch to search kind with ru+en', () => {
      expect(TOOL_LABELS.WebSearch.kind).toBe('search');
      expect(TOOL_LABELS.WebSearch.emoji).toBe('🔍');
      expect(TOOL_LABELS.WebSearch.ru).toBe('Ищу в интернете…');
      expect(TOOL_LABELS.WebSearch.en).toBe('Searching the web…');
    });
    it('maps Bash to cmd kind', () => {
      expect(TOOL_LABELS.Bash.kind).toBe('cmd');
    });
    it('maps Read/Write/Edit/Glob/Grep to file kind', () => {
      for (const t of ['Read', 'Write', 'Edit', 'Glob', 'Grep']) {
        expect(TOOL_LABELS[t].kind).toBe('file');
      }
    });
  });

  describe('refineBashLabel', () => {
    it('recognises generate_image.sh as image', () => {
      const lbl = refineBashLabel(
        'bash /home/dv/agent-env/bin/generate_image.sh --prompt "cat"',
      );
      expect(lbl).not.toBeNull();
      expect(lbl!.kind).toBe('image');
      expect(lbl!.emoji).toBe('🎨');
    });
    it('returns null for other bash commands', () => {
      expect(refineBashLabel('ls -la')).toBeNull();
      expect(refineBashLabel('python script.py')).toBeNull();
    });
  });

  describe('resolveToolLabel', () => {
    it('prefers refineBashLabel over TOOL_LABELS.Bash', () => {
      const lbl = resolveToolLabel('Bash', 'sh generate_image.sh');
      expect(lbl.kind).toBe('image');
    });
    it('falls back to TOOL_LABELS by name', () => {
      const lbl = resolveToolLabel('Read', '/etc/hosts');
      expect(lbl.kind).toBe('file');
    });
    it('returns UNKNOWN_TOOL_LABEL for unknown tool', () => {
      const lbl = resolveToolLabel('SomeCustomTool', '');
      expect(lbl).toBe(UNKNOWN_TOOL_LABEL);
      expect(lbl.kind).toBe('other');
    });
  });

  describe('PHASE_LABELS', () => {
    it('has thinking, preparing, error', () => {
      expect(PHASE_LABELS.thinking.emoji).toBe('🤔');
      expect(PHASE_LABELS.preparing.emoji).toBe('✍️');
      expect(PHASE_LABELS.error.emoji).toBe('❌');
    });
  });
});
