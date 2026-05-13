export interface ScopeDescriptor {
  key: string;
  label: string;
  description: string;
}

export const KNOWN_SCOPES: Record<string, Omit<ScopeDescriptor, 'key'>> = {
  openid: { label: 'OpenID', description: 'Идентификатор аккаунта' },
  profile: { label: 'Профиль', description: 'Имя, фамилия, аватар' },
  email: { label: 'Email', description: 'Email адрес' },
  offline_access: { label: 'Offline доступ', description: 'Поддержка работы без сети (refresh token)' },
};

export function describeScopes(scopes: string[]): ScopeDescriptor[] {
  return scopes.map((key) => {
    const known = KNOWN_SCOPES[key];
    if (known) return { key, ...known };
    return { key, label: key, description: `Доступ к ${key}` };
  });
}
