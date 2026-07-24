import { mapFolderEntry, SPECIAL_ORDER } from './mail-folders.util';

describe('mapFolderEntry', () => {
  it('maps special-use to stable role names', () => {
    expect(mapFolderEntry({ path: 'INBOX', specialUse: undefined, flags: new Set() }).role).toBe('inbox');
    expect(mapFolderEntry({ path: 'Sent', specialUse: '\\Sent', flags: new Set() }).role).toBe('sent');
    expect(mapFolderEntry({ path: 'Drafts', specialUse: '\\Drafts', flags: new Set() }).role).toBe('drafts');
    expect(mapFolderEntry({ path: 'Junk', specialUse: '\\Junk', flags: new Set() }).role).toBe('junk');
    expect(mapFolderEntry({ path: 'Trash', specialUse: '\\Trash', flags: new Set() }).role).toBe('trash');
    expect(mapFolderEntry({ path: 'My/Custom', specialUse: undefined, flags: new Set() }).role).toBe('custom');
  });
  it('orders special folders before custom', () => {
    expect(SPECIAL_ORDER.inbox).toBeLessThan(SPECIAL_ORDER.sent);
    expect(SPECIAL_ORDER.trash).toBeLessThan(SPECIAL_ORDER.custom);
  });
});
