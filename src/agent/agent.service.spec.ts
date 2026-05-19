import { Test, TestingModule } from '@nestjs/testing';
import { AgentService } from './agent.service';

// Mock exec so that its callback-based signature matches what util.promisify expects.
// When exec lacks util.promisify.custom, promisify resolves with the FIRST
// non-error argument. We therefore pass { stdout, stderr } as that first arg
// so that destructuring `const { stdout, stderr } = await execAsync(...)` works.
const mockExec = jest.fn();
jest.mock('node:child_process', () => ({
  exec: (cmd: string, opts: any, cb: any) => mockExec(cmd, opts, cb),
}));

describe('AgentService', () => {
  let service: AgentService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AgentService],
    }).compile();
    service = module.get<AgentService>(AgentService);
    mockExec.mockReset();
  });

  it('spawns SSH command targeting analyst host and returns claude stdout', async () => {
    mockExec.mockImplementation((_cmd: string, _opts: any, cb: any) => {
      cb(null, { stdout: 'pong\n', stderr: '' });
    });

    const result = await service.runAgent({
      goal: 'Reply with: pong',
      userId: 'user-123',
    });

    expect(result.finalText).toBe('pong');
    expect(result.aborted).toBe(false);
    expect(result.toolCalls).toEqual([]);

    const [cmd] = mockExec.mock.calls[0];
    expect(cmd).toContain('ssh');
    expect(cmd).toContain('dv@5.101.115.184');
    expect(cmd).toContain('claude');
    expect(cmd).toContain('--print');
    expect(cmd).toContain('Reply with: pong');
  });

  it('escapes single quotes in the goal to prevent shell injection', async () => {
    mockExec.mockImplementation((_cmd: string, _opts: any, cb: any) => {
      cb(null, { stdout: 'ok', stderr: '' });
    });

    await service.runAgent({
      goal: "what's the time?",
      userId: 'u1',
    });

    const [cmd] = mockExec.mock.calls[0];
    // The single quote must use POSIX escape: close outer quote, escaped quote, reopen
    expect(cmd).toContain("what'\\''s the time?");
    // Outer single-quote string must not be terminated prematurely
    expect(cmd).not.toContain("'what'");
  });

  it('marks aborted on non-zero exit and surfaces stderr', async () => {
    mockExec.mockImplementation((_cmd: string, _opts: any, cb: any) => {
      const err: any = new Error('Command failed');
      err.code = 1;
      err.stdout = '';
      err.stderr = 'claude: rate limited';
      cb(err);
    });

    const result = await service.runAgent({
      goal: 'go',
      userId: 'u1',
    });

    expect(result.aborted).toBe(true);
    expect(result.finalText).toContain('rate limited');
  });

  it('marks aborted on timeout', async () => {
    mockExec.mockImplementation((_cmd: string, _opts: any, cb: any) => {
      const err: any = new Error('timeout');
      err.killed = true;
      err.signal = 'SIGTERM';
      err.stdout = '';
      err.stderr = '';
      cb(err);
    });

    const result = await service.runAgent({
      goal: 'long task',
      userId: 'u1',
    });

    expect(result.aborted).toBe(true);
    expect(result.finalText.toLowerCase()).toMatch(/timeout|killed|aborted/);
  });

  it('escapes backtick injection in goal to prevent command substitution', async () => {
    mockExec.mockImplementation((_cmd: string, _opts: any, cb: any) => {
      cb(null, { stdout: 'ok', stderr: '' });
    });

    await service.runAgent({
      goal: 'echo `id`',
      userId: 'u1',
    });

    const [cmd] = mockExec.mock.calls[0];
    // Backtick must be escaped as \` inside the inner double-quoted context
    expect(cmd).toContain('\\`id\\`');
    // No unescaped backtick should appear in the command
    // The only backtick chars that appear must be preceded by a backslash
    const unescapedBacktick = /(?<!\\)`/;
    expect(cmd).not.toMatch(unescapedBacktick);
  });

  it('escapes dollar sign injection in goal to prevent variable/command expansion', async () => {
    mockExec.mockImplementation((_cmd: string, _opts: any, cb: any) => {
      cb(null, { stdout: 'ok', stderr: '' });
    });

    await service.runAgent({
      goal: '$(whoami)',
      userId: 'u1',
    });

    const [cmd] = mockExec.mock.calls[0];
    // Dollar must be escaped as \$ so the remote shell does not expand it
    expect(cmd).toContain('\\$(whoami)');
    // The unescaped sequence $( must not appear (i.e. not preceded by backslash)
    expect(cmd).not.toMatch(/(?<!\\)\$\(whoami\)/);
  });

  it('escapes backslash in goal before applying other escapes', async () => {
    mockExec.mockImplementation((_cmd: string, _opts: any, cb: any) => {
      cb(null, { stdout: 'ok', stderr: '' });
    });

    await service.runAgent({
      goal: 'test \\" inject',
      userId: 'u1',
    });

    const [cmd] = mockExec.mock.calls[0];
    // Original backslash must be doubled (\\ -> \\\\) before the quote is escaped
    // so the result is \\\\" not just \" (which would unintentionally escape the quote)
    expect(cmd).toContain('\\\\');
    // Should not crash or cause aborted result
    expect(cmd).toContain('inject');
  });

  it('surfaces stderr from a successful run without aborting', async () => {
    mockExec.mockImplementation((_cmd: string, _opts: any, cb: any) => {
      cb(null, { stdout: 'result text', stderr: 'some warning on stderr' });
    });

    const result = await service.runAgent({
      goal: 'do something',
      userId: 'u1',
    });

    // stderr does not abort; stdout is returned as finalText
    expect(result.aborted).toBe(false);
    expect(result.finalText).toBe('result text');
  });
});
