/**
 * Item kinds.
 *
 * Stored in plaintext beside each item so clients can filter and pick an icon
 * without fetching anything else. The item contents themselves are described
 * in `sharing.ts` - every item lives in a shared vault.
 */
export const VAULT_ITEM_TYPE = {
  LOGIN: 'login',
  SECURE_NOTE: 'secure_note',
  CARD: 'card',
  IDENTITY: 'identity',
  SSH_KEY: 'ssh_key',
  API_KEY: 'api_key',
} as const;

export type VaultItemType = (typeof VAULT_ITEM_TYPE)[keyof typeof VAULT_ITEM_TYPE];

export const VAULT_ITEM_TYPES: readonly VaultItemType[] = Object.values(VAULT_ITEM_TYPE);

export const VAULT_ITEM_TYPE_LABEL: Readonly<Record<VaultItemType, string>> = {
  [VAULT_ITEM_TYPE.LOGIN]: 'Login',
  [VAULT_ITEM_TYPE.SECURE_NOTE]: 'Secure note',
  [VAULT_ITEM_TYPE.CARD]: 'Credit card',
  [VAULT_ITEM_TYPE.IDENTITY]: 'Identity',
  [VAULT_ITEM_TYPE.SSH_KEY]: 'SSH key',
  [VAULT_ITEM_TYPE.API_KEY]: 'API key',
};
