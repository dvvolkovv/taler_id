import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;

  constructor(private readonly config: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.config.get<string>('email.smtp.host'),
      port: this.config.get<number>('email.smtp.port'),
      secure: false,
      requireTLS: true,
      auth: {
        user: this.config.get<string>('email.smtp.user'),
        pass: this.config.get<string>('email.smtp.pass'),
      },
    });
  }

  async sendInvite(to: string, tenantName: string, inviteToken: string, inviterName: string): Promise<void> {
    const baseUrl = this.config.get<string>('baseUrl');
    const acceptUrl = `${baseUrl}/ui/invite.html?token=${inviteToken}`;
    await this.transporter.sendMail({
      from: `"Taler ID" <${this.config.get('email.smtp.user')}>`,
      to,
      subject: `Приглашение в организацию ${tenantName}`,
      html: `<h2>Вас пригласили в <strong>${tenantName}</strong></h2>
<p>${inviterName} приглашает вас присоединиться к Taler ID.</p>
<p><a href="${acceptUrl}">Принять приглашение</a></p>
<p style="color:#888;font-size:12px;">Ссылка действительна 48 часов.</p>`,
    });
    this.logger.log(`Invite sent to ${to} for tenant ${tenantName}`);
  }

  async sendOtp(to: string, code: string, action: string): Promise<void> {
    await this.transporter.sendMail({
      from: `"Taler ID" <${this.config.get('email.smtp.user')}>`,
      to,
      subject: `Код подтверждения Taler ID: ${code}`,
      html: `<h2>Код подтверждения</h2>
<p>Действие: <strong>${action}</strong></p>
<p style="font-size:32px;letter-spacing:8px;font-weight:bold;">${code}</p>
<p style="color:#888;font-size:12px;">Код действителен 10 минут.</p>`,
    });
    this.logger.log(`OTP sent to ${to}`);
  }

  async sendKycStatusUpdate(to: string, status: 'VERIFIED' | 'REJECTED', reason?: string): Promise<void> {
    const isVerified = status === 'VERIFIED';
    await this.transporter.sendMail({
      from: `"Taler ID KYC" <${this.config.get('email.smtp.user')}>`,
      to,
      subject: isVerified ? 'Верификация успешна — Taler ID' : 'Верификация отклонена — Taler ID',
      html: isVerified
        ? '<h2 style="color:#27ae60">Верификация пройдена!</h2><p>Ваша личность подтверждена.</p>'
        : `<h2 style="color:#e74c3c">Верификация отклонена</h2>${reason ? '<p>Причина: ' + reason + '</p>' : ''}`,
    });
  }

  async verifyConnection(): Promise<boolean> {
    try {
      await this.transporter.verify();
      this.logger.log(`SMTP connected: ${this.config.get('email.smtp.host')}:${this.config.get('email.smtp.port')}`);
      return true;
    } catch (err) {
      this.logger.error(`SMTP connection failed: ${(err as Error).message}`);
      return false;
    }
  }
}
