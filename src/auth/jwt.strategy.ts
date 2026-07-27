import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { UnauthorizedException } from '@nestjs/common';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import { isApiAccessToken } from '../common/utils/access-token.util';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService) {
    const publicKeyPath = configService.get<string>('jwt.publicKeyPath') ?? '';
    const publicKey = fs.readFileSync(publicKeyPath, 'utf8');

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: publicKey,
      algorithms: ['RS256'],
    });
  }

  async validate(payload: any) {
    // A valid signature is not enough: the OIDC provider signs its ID tokens
    // with the same key, and those must never grant API access.
    if (!isApiAccessToken(payload)) {
      throw new UnauthorizedException('Invalid token');
    }
    return payload; // returns as request.user
  }
}
