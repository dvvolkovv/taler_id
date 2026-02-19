import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable, tap } from 'rxjs';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class AuditLogInterceptor implements NestInterceptor {
  private readonly logger = new Logger(AuditLogInterceptor.name);
  private readonly auditedPaths = [
    '/auth/register',
    '/auth/login',
    '/auth/logout',
    '/auth/2fa',
    '/profile',
    '/kyc',
  ];

  constructor(private readonly prisma: PrismaService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const req = context.switchToHttp().getRequest();
    const shouldAudit = this.auditedPaths.some((p) => req.url.startsWith(p));

    if (!shouldAudit) return next.handle();

    const start = Date.now();
    return next.handle().pipe(
      tap({
        next: async () => {
          const userId = req.user?.sub ?? null;
          const elapsed = Date.now() - start;
          try {
            await this.prisma.auditLog.create({
              data: {
                userId,
                action: `${req.method}:${req.url}`,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                meta: { statusCode: 200, elapsed },
              },
            });
          } catch (err) {
            this.logger.error('AuditLog write failed', err);
          }
        },
        error: async (err) => {
          const userId = req.user?.sub ?? null;
          try {
            await this.prisma.auditLog.create({
              data: {
                userId,
                action: `${req.method}:${req.url}`,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                meta: { statusCode: err?.status ?? 500, error: err?.message },
              },
            });
          } catch (e) {
            this.logger.error('AuditLog write failed (error path)', e);
          }
        },
      }),
    );
  }
}
