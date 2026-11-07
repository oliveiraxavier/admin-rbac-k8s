export interface Permission {
  apiGroup: string;
  resource: string;
  verbs: string[];
  resourceNames?: string[];
}

export interface Identity {
  name: string;
  namespace: string;
  namespaces: string[];
  createdAt: string;
  permissions: Permission[];
}

export interface IssuedToken {
  identity: Identity;
  token: string;
  expiresAt: string;
}

export interface PermissionOption {
  apiGroup: string;
  resource: string;
  label: string;
  detail: string;
  selected: Record<string, boolean>;
  resourceNames: string[];
  resourceNamesInput: string;
  allSecrets: boolean;
}

export type DurationUnit = 'hours' | 'days';
