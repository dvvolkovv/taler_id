export type FolderRole = 'inbox' | 'sent' | 'drafts' | 'junk' | 'trash' | 'custom';

export const SPECIAL_ORDER: Record<FolderRole, number> = {
  inbox: 0, sent: 1, drafts: 2, junk: 3, trash: 4, custom: 5,
};

export function mapFolderEntry(e: { path: string; specialUse?: string; flags: Set<string> }): {
  path: string; role: FolderRole;
} {
  if (e.path.toUpperCase() === 'INBOX') return { path: e.path, role: 'inbox' };
  switch (e.specialUse) {
    case '\\Sent': return { path: e.path, role: 'sent' };
    case '\\Drafts': return { path: e.path, role: 'drafts' };
    case '\\Junk': return { path: e.path, role: 'junk' };
    case '\\Trash': return { path: e.path, role: 'trash' };
    default: return { path: e.path, role: 'custom' };
  }
}
