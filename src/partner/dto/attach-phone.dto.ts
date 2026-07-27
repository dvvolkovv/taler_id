import { IsString, Matches } from 'class-validator';

export class AttachPhoneDto {
  // id_token (JWT) from the linkeon-partner-web OAuth code flow — proof the
  // user logged into their existing TalerID account. Verified server-side.
  @IsString()
  id_token!: string;

  // The SMS-verified phone (E.164) Linkeon wants attached to that account.
  @IsString()
  @Matches(/^\+?[0-9][0-9\s\-().]{5,17}$/, {
    message: 'phone must be a valid phone number (E.164, e.g. +79656445804)',
  })
  phone!: string;
}
