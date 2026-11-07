import { Injectable } from '@angular/core';
import { Identity, Permission, PermissionOption } from './models';

export const PERMISSION_VERBS = ['get', 'list', 'watch', 'create', 'delete'];

const MAX_TOKEN_TTL_DAYS = 365;
const MIN_TOKEN_TTL_SECONDS = 600;

@Injectable({ providedIn: 'root' })
export class PermissionPolicy {
  readonly verbs = PERMISSION_VERBS;

  private readonly resourceCatalog = [
    { apiGroup: '', resource: 'pods', label: 'Pods', detail: 'Contêineres e workloads' },
    { apiGroup: '', resource: 'pods/log', label: 'Logs de Pods', detail: 'Ler stdout/stderr' },
    {
      apiGroup: '',
      resource: 'pods/exec',
      label: 'Exec em Pods',
      detail: 'Executar comandos no contêiner',
    },
    {
      apiGroup: '',
      resource: 'secrets',
      label: 'Secrets',
      detail: 'Secrets de configuração e credenciais',
    },
    { apiGroup: '', resource: 'services', label: 'Services', detail: 'Serviços de rede' },
    {
      apiGroup: 'apps',
      resource: 'deployments',
      label: 'Deployments',
      detail: 'Aplicações implantadas',
    },
    {
      apiGroup: 'apps',
      resource: 'replicasets',
      label: 'ReplicaSets',
      detail: 'Réplicas de workloads',
    },
    { apiGroup: 'batch', resource: 'jobs', label: 'Jobs', detail: 'Execuções pontuais' },
    { apiGroup: 'batch', resource: 'cronjobs', label: 'CronJobs', detail: 'Execuções agendadas' },
  ];

  createOptions(): PermissionOption[] {
    return this.resourceCatalog.map((resource) => ({
      ...resource,
      selected: Object.fromEntries(this.verbs.map((verb) => [verb, false])),
      resourceNames: [],
      resourceNamesInput: '',
      allSecrets: false,
    }));
  }

  optionsFor(identity: Identity): PermissionOption[] {
    return this.resourceCatalog.map((resource) => {
      const assigned = identity.permissions.find(
        (item) => item.apiGroup === resource.apiGroup && item.resource === resource.resource,
      );
      return {
        ...resource,
        selected: Object.fromEntries(
          this.verbs.map((verb) => [verb, assigned?.verbs.includes(verb) ?? false]),
        ),
        resourceNames: assigned?.resourceNames ?? [],
        resourceNamesInput: assigned?.resourceNames?.join(', ') ?? '',
        allSecrets:
          resource.resource === 'secrets' &&
          assigned !== undefined &&
          !assigned.resourceNames?.length,
      };
    });
  }

  canSelectVerb(option: PermissionOption, verb: string): boolean {
    return (
      (option.resource !== 'pods/exec' || verb === 'create') &&
      (verb !== 'create' || option.resource === 'pods/exec') &&
      (verb !== 'delete' || option.resource === 'pods') &&
      (option.resource !== 'pods/log' || verb === 'get') &&
      (option.resource !== 'secrets' || option.allSecrets || verb === 'get')
    );
  }

  toPermissions(options: PermissionOption[]): Permission[] {
    return options
      .map((option) => ({
        ...option,
        verbs: this.verbs.filter((verb) => option.selected[verb]),
        resourceNames:
          option.resource === 'secrets'
            ? option.resourceNamesInput
                .split(',')
                .map((name) => name.trim())
                .filter(Boolean)
            : [],
      }))
      .filter((option) => option.verbs.length > 0)
      .map(({ apiGroup, resource, verbs, resourceNames, allSecrets }) => ({
        apiGroup,
        resource,
        verbs,
        ...(resource === 'secrets' && !allSecrets ? { resourceNames } : {}),
      }));
  }

  validate(
    permissions: Permission[],
    targetNamespaceCount: number,
    ttlSeconds: number,
  ): string | null {
    if (permissions.length === 0) return 'Selecione ao menos um recurso e verbo.';
    if (
      permissions.some(
        (permission) =>
          permission.resource === 'secrets' &&
          permission.resourceNames !== undefined &&
          permission.resourceNames.length === 0,
      )
    ) {
      return 'Informe os nomes específicos das Secrets que poderão ser lidos.';
    }
    if (targetNamespaceCount === 0) return 'Selecione ao menos um namespace de acesso.';
    if (!this.isValidDuration(ttlSeconds)) {
      return 'A duração deve estar entre 1 hora e 365 dias.';
    }
    return null;
  }

  isValidDuration(seconds: number): boolean {
    return (
      Number.isInteger(seconds) &&
      seconds >= MIN_TOKEN_TTL_SECONDS &&
      seconds <= MAX_TOKEN_TTL_DAYS * 24 * 60 * 60
    );
  }

  maxDuration(unit: 'hours' | 'days'): number {
    return unit === 'days' ? MAX_TOKEN_TTL_DAYS : MAX_TOKEN_TTL_DAYS * 24;
  }
}
