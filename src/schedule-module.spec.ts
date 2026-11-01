import * as fs from 'fs';
import * as path from 'path';

/** Every non-test .ts file under src. */
function sources(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) return sources(full);
    return e.name.endsWith('.ts') && !e.name.endsWith('.spec.ts') ? [full] : [];
  });
}

describe('ScheduleModule', () => {
  it('is registered once, in AppModule', () => {
    // Each ScheduleModule.forRoot() is a separate module instance with its own
    // explorer, and every explorer schedules every @Cron/@Interval in the app:
    // a second forRoot() anywhere makes each job run twice, the two runs of a
    // cron at the same instant. Feature modules get the scheduler from AppModule.
    const src = path.join(__dirname);
    const hits = sources(src)
      .filter((f) =>
        fs.readFileSync(f, 'utf8').includes('ScheduleModule.forRoot('),
      )
      .map((f) => path.relative(src, f));
    expect(hits).toEqual(['app.module.ts']);
  });
});
