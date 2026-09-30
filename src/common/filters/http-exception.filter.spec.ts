import { HttpException, HttpStatus } from '@nestjs/common';
import { HttpExceptionFilter } from './http-exception.filter';

function makeHost(request: any = { method: 'POST', url: '/partner/v1/users/m-1/link-code' }) {
  const response: any = {
    setHeader: jest.fn(),
    status: jest.fn().mockReturnThis(),
    json: jest.fn(),
  };
  const host: any = {
    switchToHttp: () => ({
      getResponse: () => response,
      getRequest: () => request,
    }),
  };
  return { host, response };
}

describe('HttpExceptionFilter', () => {
  it('sets Retry-After when the 429 body carries a numeric retryAfter', () => {
    const filter = new HttpExceptionFilter();
    const { host, response } = makeHost();
    // partner-link-code.service.ts's tooManyRequests() throws this shape without
    // ever touching res.setHeader itself — only the filter can guarantee the header.
    const exception = new HttpException(
      { message: 'too_many_requests', retryAfter: 42 },
      HttpStatus.TOO_MANY_REQUESTS,
    );
    filter.catch(exception, host);
    expect(response.setHeader).toHaveBeenCalledWith('Retry-After', '42');
    expect(response.status).toHaveBeenCalledWith(429);
  });

  it('does not set Retry-After for a 429 without a numeric retryAfter', () => {
    const filter = new HttpExceptionFilter();
    const { host, response } = makeHost();
    const exception = new HttpException('too_many_requests', HttpStatus.TOO_MANY_REQUESTS);
    filter.catch(exception, host);
    expect(response.setHeader).not.toHaveBeenCalled();
  });

  it('does not set Retry-After for a non-429 status even when the body has a retryAfter field', () => {
    const filter = new HttpExceptionFilter();
    const { host, response } = makeHost();
    const exception = new HttpException({ message: 'conflict', retryAfter: 5 }, HttpStatus.CONFLICT);
    filter.catch(exception, host);
    expect(response.setHeader).not.toHaveBeenCalled();
    expect(response.status).toHaveBeenCalledWith(409);
  });

  it('setting it again for guards that already called res.setHeader is harmless', () => {
    const filter = new HttpExceptionFilter();
    const { host, response } = makeHost();
    // PartnerKeyGuard/PartnerRateLimitGuard already call throwTooManyRequests(),
    // which sets the header itself before throwing — the filter just repeats it.
    response.setHeader('Retry-After', '60');
    const exception = new HttpException({ message: 'rate_limited', retryAfter: 60 }, HttpStatus.TOO_MANY_REQUESTS);
    filter.catch(exception, host);
    expect(response.setHeader).toHaveBeenLastCalledWith('Retry-After', '60');
  });
});
