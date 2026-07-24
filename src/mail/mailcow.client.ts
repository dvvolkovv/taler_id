import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios, { AxiosInstance } from 'axios';

export interface MailcowAppPasswd {
  id: number;
  name: string;
  created: string;
}

@Injectable()
export class MailcowClient {
  private readonly logger = new Logger(MailcowClient.name);
  private readonly http: AxiosInstance;

  constructor(config: ConfigService) {
    this.http = axios.create({
      baseURL: `${config.get<string>('mail.mailcowUrl')}/api/v1`,
      headers: { 'X-API-Key': config.get<string>('mail.mailcowApiKey') ?? '' },
      timeout: 15000,
    });
  }

  /** Mailcow отвечает 200 даже на ошибки — успех определяем по type=success в массиве. */
  private ensureSuccess(op: string, data: unknown): void {
    const arr = Array.isArray(data) ? data : [data];
    const ok = arr.some((r: any) => r?.type === 'success');
    if (!ok) {
      // I4: редактируем чувствительные поля перед логированием
      const redacted = JSON.stringify(data).replace(/"(password|password2|app_passwd|app_passwd2)":"[^"]*"/g, '"$1":"***"');
      this.logger.error(`mailcow ${op} failed: ${redacted.slice(0, 500)}`);
      throw new Error(`mailcow_${op}_failed`);
    }
  }

  async mailboxExists(username: string): Promise<boolean> {
    const res = await this.http.get(`/get/mailbox/${encodeURIComponent(username)}`);
    return !!res.data && typeof res.data === 'object' && 'username' in res.data;
  }

  async setMailboxPassword(username: string, password: string): Promise<void> {
    const res = await this.http.post('/edit/mailbox', {
      items: [username],
      attr: { password, password2: password },
    });
    this.ensureSuccess('edit_mailbox_password', res.data);
  }

  async createMailbox(localpart: string, domain: string, password: string, quotaMb: number, name: string): Promise<void> {
    // Retry-идемпотентность: если ящик уже есть (наша прошлая попытка успела его
    // создать до падения), выравниваем пароль под наш сохранённый секрет.
    // Чужой (другого env) ящик сюда не попадает — availability сверяется с Mailcow
    // до создания записи в БД.
    if (await this.mailboxExists(`${localpart}@${domain}`)) {
      await this.setMailboxPassword(`${localpart}@${domain}`, password);
      return;
    }
    const res = await this.http.post('/add/mailbox', {
      local_part: localpart,
      domain,
      name,
      password,
      password2: password,
      quota: String(quotaMb),
      active: '1',
      force_pw_update: '0',
      tls_enforce_in: '1',
      tls_enforce_out: '1',
    });
    this.ensureSuccess('add_mailbox', res.data);
  }

  async setMailboxActive(username: string, active: boolean): Promise<void> {
    const res = await this.http.post('/edit/mailbox', {
      items: [username],
      attr: { active: active ? '1' : '0' },
    });
    this.ensureSuccess('edit_mailbox', res.data);
  }

  async deleteMailbox(username: string): Promise<void> {
    const res = await this.http.post('/delete/mailbox', [username]);
    this.ensureSuccess('delete_mailbox', res.data);
  }

  async createAppPassword(username: string, label: string, password: string): Promise<number> {
    // Minor-3: снимаем snapshot id'ов до создания, чтобы не путаться при дублирующихся label
    const before = await this.listAppPasswords(username);
    const maxId = Math.max(0, ...before.map((p) => p.id));

    const res = await this.http.post('/add/app-passwd', {
      username,
      app_name: label,
      app_passwd: password,
      app_passwd2: password,
      active: '1',
      protocols: ['imap_access', 'smtp_access'],
    });
    this.ensureSuccess('add_app_passwd', res.data);
    // id созданного пароля Mailcow в ответе не отдаёт — перечитываем список
    const list = await this.listAppPasswords(username);
    // берём запись с id строго больше maxId (атомарно определяем созданную)
    const created = list.filter((p) => p.id > maxId).sort((a, b) => a.id - b.id)[0];
    if (!created) throw new Error('mailcow_app_passwd_not_found_after_create');
    return created.id;
  }

  async listAppPasswords(username: string): Promise<MailcowAppPasswd[]> {
    const res = await this.http.get(`/get/app-passwd/all/${encodeURIComponent(username)}`);
    return Array.isArray(res.data) ? res.data : [];
  }

  async deleteAppPassword(id: number): Promise<void> {
    const res = await this.http.post('/delete/app-passwd', [String(id)]);
    this.ensureSuccess('delete_app_passwd', res.data);
  }
}
