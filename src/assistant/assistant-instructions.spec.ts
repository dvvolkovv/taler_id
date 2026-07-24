import { AssistantInstructionsService } from './assistant-instructions.service';

describe('AssistantInstructionsService', () => {
  const service = new AssistantInstructionsService();

  it('returns ru body for locale=ru', () => {
    const res = service.getInstructions('ru');
    expect(res.locale).toBe('ru');
    expect(res.body).toContain('AI АНАЛИТИК');
    expect(res.body).toContain('ЗАДАЧА ДЛЯ АНАЛИТИКА');
    expect(res.body).toContain('ask_analyst ПОВТОРНО');
    expect(res.body).toContain('КАТЕГОРИЧЕСКИ ЗАПРЕЩЕНО');
    expect(res.body).toContain('ПОЧТА (@talerid.io)');
    expect(res.body).toContain('check_mail');
    expect(res.updatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('returns en body for locale=en', () => {
    const res = service.getInstructions('en');
    expect(res.locale).toBe('en');
    expect(res.body).toContain('AI ANALYST');
    expect(res.body).toContain('MAIL (@talerid.io)');
  });

  it('falls back to en for unknown locale', () => {
    const res = service.getInstructions('zh');
    expect(res.locale).toBe('en');
    expect(res.body).toContain('AI ANALYST');
    expect(res.body).toContain('{{LANG_NAME}}');
  });

  it('falls back to en when locale is missing', () => {
    const res = service.getInstructions(undefined);
    expect(res.locale).toBe('en');
  });

  it('keeps {{NOW}} placeholder for client-side substitution', () => {
    expect(service.getInstructions('ru').body).toContain('{{NOW}}');
    expect(service.getInstructions('en').body).toContain('{{NOW}}');
  });
});
