import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;

  constructor(private readonly config: ConfigService) {
    const host = this.config.get<string>('email.smtp.host');

    // This connection carries login OTP codes and the SMTP credentials
    // themselves, so an unverified peer means anyone able to intercept the
    // route can read both. Verification is nevertheless OFF by default,
    // because mail.taler.tirol still presents a self-signed certificate that
    // expired in October 2024 — turning it on before the certificate is fixed
    // would stop OTP delivery, i.e. stop people signing in.
    //
    // Flip SMTP_TLS_REJECT_UNAUTHORIZED=true the moment that host gets a valid
    // certificate; nothing else needs to change.
    const rejectUnauthorized =
      process.env.SMTP_TLS_REJECT_UNAUTHORIZED === 'true';

    if (!rejectUnauthorized) {
      this.logger.warn(
        `SMTP TLS certificate verification is disabled for ${host} — OTP codes ` +
          'and SMTP credentials are exposed to an active network attacker. ' +
          'Fix the certificate and set SMTP_TLS_REJECT_UNAUTHORIZED=true.',
      );
    }

    this.transporter = nodemailer.createTransport({
      host,
      port: this.config.get<number>('email.smtp.port'),
      secure: false,
      requireTLS: true,
      tls: { rejectUnauthorized },
      auth: {
        user: this.config.get<string>('email.smtp.user'),
        pass: this.config.get<string>('email.smtp.pass'),
      },
    });
  }

  async sendInvite(
    to: string,
    tenantName: string,
    inviteToken: string,
    inviterName: string,
  ): Promise<void> {
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

  /**
   * Код, которым человек подтверждает, что сам подключает приложение-партнёра
   * (nadi) к своему существующему аккаунту. Без кода партнёр не получает
   * доступ к его чатам. Язык — из профиля TalerID: ru или en.
   */
  async sendPartnerLinkCode(
    to: string,
    code: string,
    partnerName: string,
    language: string,
  ): Promise<void> {
    const name = escapeHtml(partnerName);
    const ru = language === 'ru';
    await this.transporter.sendMail({
      from: `"Taler ID" <${this.config.get('email.smtp.user')}>`,
      to,
      subject: ru
        ? `Код для подключения ${partnerName} к Taler ID: ${code}`
        : `Code to connect ${partnerName} to Taler ID: ${code}`,
      html: ru
        ? `<h2>Подключение ${name} к вашему аккаунту Taler ID</h2>
<p>Приложение <strong>${name}</strong> просит доступ к вашим чатам Taler ID: оно сможет показывать ваши личные чаты и группы и писать в них от вашего имени.</p>
<p>Если это вы — введите код в приложении ${name}:</p>
<p style="font-size:32px;letter-spacing:8px;font-weight:bold;">${code}</p>
<p style="color:#888;font-size:12px;">Код действителен 10 минут. Если вы ничего не подключали — просто проигнорируйте письмо: без кода доступ не откроется.</p>`
        : `<h2>Connecting ${name} to your Taler ID account</h2>
<p>The <strong>${name}</strong> app asks for access to your Taler ID chats: it will be able to show your direct chats and groups and write to them on your behalf.</p>
<p>If this is you, enter the code in the ${name} app:</p>
<p style="font-size:32px;letter-spacing:8px;font-weight:bold;">${code}</p>
<p style="color:#888;font-size:12px;">The code is valid for 10 minutes. If you did not connect anything, just ignore this email: without the code no access is granted.</p>`,
    });
    this.logger.log(`Partner link code sent to ${to} for ${partnerName}`);
  }

  async sendKycStatusUpdate(
    to: string,
    status: 'VERIFIED' | 'REJECTED',
    reason?: string,
  ): Promise<void> {
    const isVerified = status === 'VERIFIED';
    await this.transporter.sendMail({
      from: `"Taler ID KYC" <${this.config.get('email.smtp.user')}>`,
      to,
      subject: isVerified
        ? 'Верификация успешна — Taler ID'
        : 'Верификация отклонена — Taler ID',
      html: isVerified
        ? '<h2 style="color:#27ae60">Верификация пройдена!</h2><p>Ваша личность подтверждена.</p>'
        : `<h2 style="color:#e74c3c">Верификация отклонена</h2>${reason ? '<p>Причина: ' + reason + '</p>' : ''}`,
    });
  }

  async verifyConnection(): Promise<boolean> {
    try {
      await this.transporter.verify();
      this.logger.log(
        `SMTP connected: ${this.config.get('email.smtp.host')}:${this.config.get('email.smtp.port')}`,
      );
      return true;
    } catch (err) {
      this.logger.error(`SMTP connection failed: ${(err as Error).message}`);
      return false;
    }
  }
}

function escapeHtml(value: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  };
  return value.replace(/[&<>"']/g, (ch) => map[ch]);
}
