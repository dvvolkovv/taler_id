import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { Logger } from '@nestjs/common';
import { GroupCallService } from '../group-call.service';

/**
 * BullMQ worker for the `group-call-timeouts` queue. Processes `timeout-invite`
 * jobs scheduled by `GroupCallService.createCall` / `inviteMore` with a 30s
 * delay. The actual transition logic lives in `GroupCallService.handleInviteTimeout`
 * — this processor is a thin BullMQ adapter.
 *
 * Errors are rethrown so BullMQ retries (default attempts=1; configure if
 * needed). The handler is idempotent so retries are safe.
 */
@Processor('group-call-timeouts')
export class GroupCallTimeoutProcessor extends WorkerHost {
  private readonly logger = new Logger(GroupCallTimeoutProcessor.name);

  constructor(private readonly service: GroupCallService) {
    super();
  }

  async process(job: Job<{ inviteId: string }>): Promise<void> {
    if (job.name !== 'timeout-invite') {
      this.logger.warn(`Unknown job name '${job.name}' on timeouts queue`);
      return;
    }
    try {
      await this.service.handleInviteTimeout(job.data.inviteId);
    } catch (e: any) {
      this.logger.error(
        `timeout-invite failed for ${job.data.inviteId}: ${e?.message ?? e}`,
      );
      throw e;
    }
  }
}
