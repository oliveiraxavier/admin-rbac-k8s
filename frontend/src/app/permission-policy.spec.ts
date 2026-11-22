import { PermissionPolicy } from './permission-policy';
import { Identity, PermissionOption } from './models';

describe('PermissionPolicy', () => {
  let policy: PermissionPolicy;

  beforeEach(() => {
    policy = new PermissionPolicy();
  });

  it('creates all resources with no verbs selected', () => {
    const options = policy.createOptions();

    expect(options.length).toBeGreaterThan(0);
    expect(options.every((option) => Object.values(option.selected).every((selected) => !selected))).toBe(true);
  });

  it('restores an identity permissions and secret names', () => {
    const identity: Identity = {
      name: 'reader',
      namespace: 'apps',
      namespaces: ['apps', 'shared'],
      createdAt: '2026-11-21T00:00:00Z',
      permissions: [
        { apiGroup: '', resource: 'pods', verbs: ['get', 'list'] },
        { apiGroup: '', resource: 'secrets', verbs: ['get'], resourceNames: ['database', 'api-key'] },
      ],
    };

    const options = policy.optionsFor(identity);
    const pods = options.find((option) => option.resource === 'pods');
    const secrets = options.find((option) => option.resource === 'secrets');

    expect(pods?.selected['get']).toBe(true);
    expect(pods?.selected['list']).toBe(true);
    expect(secrets?.resourceNamesInput).toBe('database, api-key');
    expect(secrets?.allSecrets).toBe(false);
  });

  it('limits verb selection by resource', () => {
    const podsExec = policy.createOptions().find((option) => option.resource === 'pods/exec')!;
    const podsLog = policy.createOptions().find((option) => option.resource === 'pods/log')!;
    const secrets = policy.createOptions().find((option) => option.resource === 'secrets')!;

    expect(policy.canSelectVerb(podsExec, 'create')).toBe(true);
    expect(policy.canSelectVerb(podsExec, 'delete')).toBe(false);
    expect(policy.canSelectVerb(podsLog, 'list')).toBe(false);
    expect(policy.canSelectVerb(secrets, 'delete')).toBe(false);
  });

  it('converts secret names and omits unselected resources', () => {
    const options = policy.createOptions();
    const secrets = options.find((option) => option.resource === 'secrets')!;
    secrets.selected['get'] = true;
    secrets.resourceNamesInput = ' database, api-key, , ';

    const permissions = policy.toPermissions(options);

    expect(permissions).toContainEqual({
      apiGroup: '',
      resource: 'secrets',
      verbs: ['get'],
      resourceNames: ['database', 'api-key'],
    });
  });

  it('validates namespace, permissions and duration', () => {
    expect(policy.validate([], 1, 60 * 60)).toBe('Selecione ao menos um recurso e verbo.');
    expect(policy.validate([{ apiGroup: '', resource: 'pods', verbs: ['get'] }], 0, 60 * 60))
      .toBe('Selecione ao menos um namespace de acesso.');
    expect(policy.validate([{ apiGroup: '', resource: 'pods', verbs: ['get'] }], 1, 60))
      .toBe('A duração deve estar entre 1 hora e 365 dias.');
  });

  it('requires specific secret names unless all secrets are selected', () => {
    const options = policy.createOptions();
    const secrets = options.find((option) => option.resource === 'secrets')!;
    secrets.selected['get'] = true;
    secrets.allSecrets = false;
    const permissions = policy.toPermissions(options);

    expect(policy.validate(permissions, 1, 60 * 60))
      .toBe('Informe os nomes específicos das Secrets que poderão ser lidos.');
  });

  it('accepts all-secrets scope', () => {
    const options: PermissionOption[] = policy.createOptions();
    const secrets = options.find((option) => option.resource === 'secrets')!;
    secrets.allSecrets = true;
    secrets.selected['list'] = true;
    secrets.selected['watch'] = true;

    const permissions = policy.toPermissions(options);

    expect(policy.validate(permissions, 1, 60 * 60)).toBeNull();
  });
});
