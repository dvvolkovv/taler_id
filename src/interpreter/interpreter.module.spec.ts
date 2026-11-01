import { Test } from '@nestjs/testing';
import { BillingModule } from '../billing/billing.module';
import { GatingService } from '../billing/services/gating.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { InterpreterController } from './interpreter.controller';
import { InterpreterModule } from './interpreter.module';
import { InterpreterReconciler } from './interpreter.reconciler';

// The real BillingModule pulls in the whole app's module graph, which jest
// cannot load (oidc.module.ts imports './….js' paths). Its providers are
// stubbed below anyway.
jest.mock('../billing/billing.module', () => ({
  BillingModule: class BillingModule {},
}));

describe('InterpreterModule', () => {
  it('takes billing from BillingModule', () => {
    expect(Reflect.getMetadata('imports', InterpreterModule)).toContain(
      BillingModule,
    );
  });

  it('wires its own providers, given the app-wide ones', async () => {
    // Only what the module gets from outside is stubbed: a class imported
    // with `import type` would compile, yet leave Nest nothing to inject.
    const moduleRef = await Test.createTestingModule({
      controllers: Reflect.getMetadata('controllers', InterpreterModule),
      providers: [
        ...Reflect.getMetadata('providers', InterpreterModule),
        { provide: PrismaService, useValue: {} },
        { provide: RedisService, useValue: {} },
        { provide: GatingService, useValue: {} },
      ],
    }).compile();

    expect(moduleRef.get(InterpreterController)).toBeInstanceOf(
      InterpreterController,
    );
    expect(moduleRef.get(InterpreterReconciler)).toBeInstanceOf(
      InterpreterReconciler,
    );
  });
});
