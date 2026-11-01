import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { AgentEndedDto } from './agent-ended.dto';
import { CreateInterpreterSessionDto } from './create-interpreter-session.dto';
import { JoinInterpreterSessionDto } from './join-interpreter-session.dto';

async function messages(
  cls: new () => object,
  plain: Record<string, unknown>,
): Promise<string[]> {
  const errors = await validate(plainToInstance(cls, plain));
  return errors.flatMap((e) => Object.values(e.constraints ?? {}));
}

describe('interpreter DTOs', () => {
  it('take a bare language code; any other shape is unsupported_language', async () => {
    expect(await messages(CreateInterpreterSessionDto, { lang: 'ru' })).toEqual(
      [],
    );
    for (const lang of ['pt-BR', 'RU', 'russian', '']) {
      expect(await messages(CreateInterpreterSessionDto, { lang })).toEqual([
        'unsupported_language',
      ]);
    }
    expect(
      await messages(JoinInterpreterSessionDto, {
        code: 'ABCDEFGH',
        lang: 'x',
      }),
    ).toEqual(['unsupported_language']);
  });

  it('take the code as typed, within a sane length', async () => {
    expect(
      await messages(JoinInterpreterSessionDto, {
        code: 'abcd-efgh',
        lang: 'de',
      }),
    ).toEqual([]);
    expect(
      await messages(JoinInterpreterSessionDto, {
        code: 'A'.repeat(33),
        lang: 'de',
      }),
    ).toHaveLength(1);
    expect(
      await messages(JoinInterpreterSessionDto, { code: 42, lang: 'de' }),
    ).not.toEqual([]);
  });

  it('take only the endings the agent reports', async () => {
    for (const reason of ['partner_left', 'agent_lost', 'translation_failed']) {
      expect(await messages(AgentEndedDto, { reason })).toEqual([]);
    }
    expect(await messages(AgentEndedDto, { reason: 'hangup' })).toHaveLength(1);
    expect(await messages(AgentEndedDto, {})).toHaveLength(1);
  });
});
