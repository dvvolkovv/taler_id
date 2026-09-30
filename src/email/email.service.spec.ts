import { EmailService } from './email.service';

function make() {
  const values: Record<string, unknown> = {
    'email.smtp.host': 'smtp.test',
    'email.smtp.port': 587,
    'email.smtp.user': 'noreply@talerid.io',
    'email.smtp.pass': 'x',
  };
  const config: any = { get: jest.fn((key: string) => values[key]) };
  const service = new EmailService(config);
  const sendMail = jest.fn().mockResolvedValue({});
  (service as any).transporter = { sendMail };
  return { service, sendMail };
}

describe('EmailService.sendPartnerLinkCode', () => {
  it('sends a Russian letter to ru accounts with the code in the subject', async () => {
    const { service, sendMail } = make();
    await service.sendPartnerLinkCode('ivan@example.com', '123456', 'Nadi', 'ru');
    const mail = sendMail.mock.calls[0][0];
    expect(mail.to).toBe('ivan@example.com');
    expect(mail.subject).toBe('Код для подключения Nadi к Taler ID: 123456');
    expect(mail.html).toContain('123456');
    expect(mail.html).toContain('проигнорируйте');
  });

  it('writes in English to everyone else', async () => {
    const { service, sendMail } = make();
    await service.sendPartnerLinkCode('ivan@example.com', '123456', 'Nadi', 'uk');
    expect(sendMail.mock.calls[0][0].subject).toBe('Code to connect Nadi to Taler ID: 123456');
  });

  it('escapes the partner name in HTML', async () => {
    const { service, sendMail } = make();
    await service.sendPartnerLinkCode('ivan@example.com', '123456', '<b>X</b>', 'en');
    const html = sendMail.mock.calls[0][0].html as string;
    expect(html).not.toContain('<b>X</b>');
    expect(html).toContain('&lt;b&gt;X&lt;/b&gt;');
  });
});
