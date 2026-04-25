import { ArgumentsHost, Catch, ExceptionFilter, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { InsufficientFundsException } from '../exceptions/insufficient-funds.exception';
import { FeatureDisabledException } from '../exceptions/feature-disabled.exception';

@Catch(InsufficientFundsException, FeatureDisabledException)
export class BillingExceptionFilter
  implements ExceptionFilter<InsufficientFundsException | FeatureDisabledException>
{
  catch(exception: InsufficientFundsException | FeatureDisabledException, host: ArgumentsHost) {
    const res = host.switchToHttp().getResponse<Response>();

    if (exception instanceof InsufficientFundsException) {
      res.status(HttpStatus.PAYMENT_REQUIRED).json({
        error: 'insufficient_funds',
        featureKey: exception.featureKey,
        requiredPlanck: exception.requiredPlanck.toString(),
        availablePlanck: exception.availablePlanck.toString(),
        suggestedPackage: exception.suggestedPackage,
      });
      return;
    }

    res.status(HttpStatus.FORBIDDEN).json({
      error: 'feature_disabled',
      featureKey: exception.featureKey,
    });
  }
}
