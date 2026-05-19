import { Test, TestingModule } from '@nestjs/testing';
import { AgentService } from './agent.service';

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
    // The single quote in "what's" must NOT close the outer shell string unsafely
    expect(cmd).not.toMatch(/'what's/);
    // It should be escaped — pattern depends on chosen escaping. The goal text
    // must still be reconstructible inside the inner shell.
    expect(cmd).toMatch(/what.{1,4}s the time\?/);
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
});
