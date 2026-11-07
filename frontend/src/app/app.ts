import { HttpErrorResponse } from '@angular/common/http';
import { DatePipe } from '@angular/common';
import { Component, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { AccessApi } from './access-api';
import { DurationUnit, Identity, IssuedToken, PermissionOption } from './models';
import { PermissionPolicy, PERMISSION_VERBS } from './permission-policy';

@Component({
  imports: [DatePipe, FormsModule],
  selector: 'app-root',
  styleUrl: './app.scss',
  templateUrl: './app.html',
})
export class App {
  protected readonly connected = signal(false);
  protected readonly loading = signal(false);
  protected readonly busy = signal(false);
  protected readonly identities = signal<Identity[]>([]);
  protected readonly namespaces = signal<string[]>([]);
  protected readonly formOpen = signal(false);
  protected readonly namespaceMenuOpen = signal(false);
  protected readonly tokenResult = signal<IssuedToken | null>(null);
  protected readonly issueTarget = signal<Identity | null>(null);
  protected readonly errorMessage = signal('');
  protected readonly formError = signal('');
  protected readonly issueError = signal('');
  protected readonly notice = signal('');
  protected readonly filter = signal('');
  protected apiKey = '';
  protected name = '';
  protected namespace = '';
  protected targetNamespaces: string[] = [];
  protected ttlValue = 8;
  protected ttlUnit: DurationUnit = 'hours';
  protected issueDuration = 8;
  protected issueUnit: DurationUnit = 'hours';
  protected editingIdentity: Identity | null = null;
  protected permissions: PermissionOption[] = [];

  protected readonly verbs = PERMISSION_VERBS;

  constructor(
    private readonly api: AccessApi,
    private readonly permissionPolicy: PermissionPolicy,
  ) {}

  protected async connect(): Promise<void> {
    const token = this.apiKey.trim();
    if (!token) {
      this.errorMessage.set('Informe o segredo da API.');
      return;
    }
    this.errorMessage.set('');
    this.loading.set(true);
    this.api.connect(token);
    try {
      const [namespaces, identities] = await Promise.all([this.api.namespaces(), this.api.list()]);
      this.namespaces.set(namespaces);
      this.identities.set(identities);
      this.connected.set(true);
      this.apiKey = '';
    } catch (error) {
      this.api.disconnect();
      this.errorMessage.set(this.describeError(error));
    } finally {
      this.loading.set(false);
    }
  }

  protected disconnect(): void {
    this.api.disconnect();
    this.connected.set(false);
    this.identities.set([]);
    this.namespaces.set([]);
    this.apiKey = '';
    this.tokenResult.set(null);
    this.formOpen.set(false);
    this.issueTarget.set(null);
    this.errorMessage.set('');
    this.formError.set('');
    this.issueError.set('');
  }

  protected async refresh(): Promise<void> {
    this.loading.set(true);
    this.errorMessage.set('');
    try {
      this.identities.set(await this.api.list());
      this.notice.set('Lista atualizada.');
    } catch (error) {
      this.errorMessage.set(this.describeError(error));
    } finally {
      this.loading.set(false);
    }
  }

  protected visibleIdentities(): Identity[] {
    const query = this.filter().trim().toLowerCase();
    if (!query) return this.identities();
    return this.identities().filter((identity) =>
      `${identity.name} ${identity.namespace} ${identity.namespaces.join(' ')} ${identity.permissions.map((item) => item.resource).join(' ')}`
        .toLowerCase()
        .includes(query),
    );
  }

  protected beginCreate(): void {
    this.namespaceMenuOpen.set(false);
    this.editingIdentity = null;
    this.name = '';
    this.namespace = this.namespaces()[0] ?? '';
    this.targetNamespaces = this.namespace ? [this.namespace] : [];
    this.ttlValue = 8;
    this.ttlUnit = 'hours';
    this.permissions = this.permissionPolicy.createOptions();
    this.errorMessage.set('');
    this.formError.set('');
    this.formOpen.set(true);
  }

  protected beginEdit(identity: Identity): void {
    this.namespaceMenuOpen.set(false);
    this.editingIdentity = identity;
    this.name = identity.name;
    this.namespace = identity.namespace;
    this.targetNamespaces = [...identity.namespaces];
    this.permissions = this.permissionPolicy.optionsFor(identity);
    this.errorMessage.set('');
    this.formError.set('');
    this.formOpen.set(true);
  }

  protected closeForm(): void {
    this.formOpen.set(false);
    this.namespaceMenuOpen.set(false);
    this.formError.set('');
  }

  protected toggleNamespaceMenu(): void {
    this.namespaceMenuOpen.update((open) => !open);
  }

  protected namespaceSummary(): string {
    if (this.targetNamespaces.length === 0) return 'Selecione namespaces';
    if (this.targetNamespaces.length <= 2) return this.targetNamespaces.join(', ');
    return `${this.targetNamespaces.length} namespaces selecionados`;
  }

  protected togglePermission(option: PermissionOption, verb: string, event: Event): void {
    option.selected[verb] = (event.target as HTMLInputElement).checked;
  }

  protected hasVerb(option: PermissionOption, verb: string): boolean {
    return option.selected[verb] ?? false;
  }

  protected canSelectVerb(option: PermissionOption, verb: string): boolean {
    return this.permissionPolicy.canSelectVerb(option, verb);
  }

  protected toggleSecretScope(option: PermissionOption, event: Event): void {
    option.allSecrets = (event.target as HTMLInputElement).checked;
    option.selected['list'] = option.allSecrets;
    option.selected['watch'] = option.allSecrets;
  }

  protected allVerbSelected(verb: string): boolean {
    const applicable = this.permissions.filter((option) => this.canSelectVerb(option, verb));
    return applicable.length > 0 && applicable.every((option) => this.hasVerb(option, verb));
  }

  protected someVerbSelected(verb: string): boolean {
    return (
      this.permissions.some(
        (option) => this.canSelectVerb(option, verb) && this.hasVerb(option, verb),
      ) && !this.allVerbSelected(verb)
    );
  }

  protected toggleAllVerb(verb: string, event: Event): void {
    const selected = (event.target as HTMLInputElement).checked;
    if (selected && (verb === 'list' || verb === 'watch')) {
      const secrets = this.permissions.find((option) => option.resource === 'secrets');
      if (secrets) secrets.allSecrets = true;
    }
    for (const option of this.permissions) {
      if (this.canSelectVerb(option, verb)) option.selected[verb] = selected;
    }
  }

  protected hasTargetNamespace(namespace: string): boolean {
    return this.targetNamespaces.includes(namespace);
  }

  protected toggleTargetNamespace(namespace: string, event: Event): void {
    const checked = (event.target as HTMLInputElement).checked;
    this.targetNamespaces = checked
      ? [...this.targetNamespaces, namespace]
      : this.targetNamespaces.filter((item) => item !== namespace);
  }

  protected selectionCount(): number {
    return this.permissions.filter((option) => Object.values(option.selected).some(Boolean)).length;
  }

  protected maxDuration(unit: DurationUnit): number {
    return this.permissionPolicy.maxDuration(unit);
  }

  private durationInSeconds(value: number, unit: DurationUnit): number {
    return Number(value) * (unit === 'days' ? 24 * 60 * 60 : 60 * 60);
  }

  protected async saveIdentity(): Promise<void> {
    const selected = this.permissionPolicy.toPermissions(this.permissions);
    const ttlSeconds = this.durationInSeconds(this.ttlValue, this.ttlUnit);
    const validationError = this.permissionPolicy.validate(
      selected,
      this.targetNamespaces.length,
      ttlSeconds,
    );
    if (validationError) {
      this.formError.set(validationError);
      return;
    }
    this.busy.set(true);
    this.formError.set('');
    try {
      if (this.editingIdentity) {
        await this.api.update(this.editingIdentity, this.targetNamespaces, selected);
        this.notice.set('Permissões atualizadas.');
        this.formOpen.set(false);
        await this.refresh();
      } else {
        const result = await this.api.create({
          name: this.name.trim(),
          namespace: this.namespace,
          targetNamespaces: this.targetNamespaces,
          ttlSeconds,
          permissions: selected,
        });
        this.formOpen.set(false);
        this.tokenResult.set(result);
        await this.refresh();
      }
    } catch (error) {
      this.formError.set(this.describeError(error));
    } finally {
      this.busy.set(false);
    }
  }

  protected async deleteIdentity(identity: Identity): Promise<void> {
    if (
      !window.confirm(
        `Excluir ${identity.name} em ${identity.namespace}? O token deixará de funcionar.`,
      )
    )
      return;
    this.busy.set(true);
    this.errorMessage.set('');
    try {
      await this.api.remove(identity);
      this.identities.update((items) =>
        items.filter(
          (item) => item.name !== identity.name || item.namespace !== identity.namespace,
        ),
      );
      this.notice.set('Identidade removida.');
    } catch (error) {
      this.errorMessage.set(this.describeError(error));
    } finally {
      this.busy.set(false);
    }
  }

  protected beginIssue(identity: Identity): void {
    this.issueTarget.set(identity);
    this.issueDuration = 8;
    this.issueUnit = 'hours';
    this.errorMessage.set('');
    this.issueError.set('');
  }

  protected async issueToken(): Promise<void> {
    const target = this.issueTarget();
    if (!target) return;
    const ttlSeconds = this.durationInSeconds(this.issueDuration, this.issueUnit);
    if (!this.permissionPolicy.isValidDuration(ttlSeconds)) {
      this.issueError.set('A duração deve estar entre 1 hora e 365 dias.');
      return;
    }
    this.busy.set(true);
    this.issueError.set('');
    try {
      this.tokenResult.set(await this.api.issue(target, ttlSeconds));
      this.issueTarget.set(null);
    } catch (error) {
      this.issueError.set(this.describeError(error));
    } finally {
      this.busy.set(false);
    }
  }

  protected closeToken(): void {
    this.tokenResult.set(null);
  }

  protected async copyToken(): Promise<void> {
    const token = this.tokenResult()?.token;
    if (!token) return;
    await navigator.clipboard.writeText(token);
    this.notice.set('Token copiado.');
  }

  protected summarize(identity: Identity): string {
    const resources = identity.permissions.length;
    return `${resources} ${resources === 1 ? 'recurso' : 'recursos'} · ${identity.permissions.some((item) => item.verbs.some((verb) => verb !== 'get')) ? 'leitura ampliada' : 'somente get'}`;
  }

  protected trackIdentity(_index: number, identity: Identity): string {
    return `${identity.namespace}/${identity.name}`;
  }

  private describeError(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      return error.error?.error ?? `Falha na API (${error.status || 'rede'}).`;
    }
    return error instanceof Error ? error.message : 'Não foi possível concluir a operação.';
  }
}
