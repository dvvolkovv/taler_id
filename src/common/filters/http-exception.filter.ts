import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: HttpException, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status = exception.getStatus();
    const exceptionResponse = exception.getResponse();

    const baseBody = {
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      message:
        typeof exceptionResponse === 'string'
          ? exceptionResponse
          : (exceptionResponse as any).message || 'Internal server error',
      error:
        typeof exceptionResponse === 'object'
          ? (exceptionResponse as any).error
          : undefined,
    };
    // Preserve any additional fields on the exception response object so callers
    // can attach domain context (e.g. ConflictException with a `currentNote`
    // payload for optimistic-concurrency clients). The base keys above always win.
    const extras =
      typeof exceptionResponse === 'object' && exceptionResponse !== null
        ? Object.fromEntries(
            Object.entries(exceptionResponse).filter(
              ([k]) => !['statusCode', 'message', 'error'].includes(k),
            ),
          )
        : {};
    const errorBody = { ...extras, ...baseBody };

    if (status >= 500) {
      this.logger.error(
        `${request.method} ${request.url} → ${status}`,
        exception.stack,
      );
    } else if (status === 401 || status === 403) {
      this.logger.warn(
        `${request.method} ${request.url} → ${status} from ${request.ip}`,
      );
    }

    // Не все источники 429 сами ставят заголовок (partner-link-code.service.ts's
    // tooManyRequests() кладёт retryAfter только в тело) — филтр гарантирует его
    // для любого 429 с числовым retryAfter. Повторная установка тем же значением
    // для guard'ов, что уже вызвали throwTooManyRequests(), безвредна.
    const retryAfter = (exceptionResponse as any)?.retryAfter;
    if (status === 429 && typeof retryAfter === 'number') {
      response.setHeader('Retry-After', String(retryAfter));
    }

    response.status(status).json(errorBody);
  }
}
