import { Injectable, signal } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { Identity, IssuedToken, Permission } from './models';

export interface AuthSession {
  provider: 'authentik' | 'token';
  authenticated: boolean;
  user?: { name?: string; email?: string };
}

@Injectable({ providedIn: 'root' })
export class AccessApi {
  private readonly baseUrl = '/api/v1';
  private readonly adminToken = signal<string | null>(null);

  constructor(private readonly http: HttpClient) {}

  connect(token?: string): void {
    this.adminToken.set(token ?? null);
  }

  disconnect(): void {
    this.adminToken.set(null);
  }

  async session(): Promise<AuthSession> {
    return firstValueFrom(
      this.http.get<AuthSession>('/auth/session', { withCredentials: true }),
    );
  }

  async namespaces(): Promise<string[]> {
    return firstValueFrom(
      this.http.get<string[]>(`${this.baseUrl}/namespaces`, {
        headers: this.headers(),
        withCredentials: true,
      }),
    );
  }

  async list(): Promise<Identity[]> {
    return firstValueFrom(
      this.http.get<Identity[]>(`${this.baseUrl}/tokens`, {
        headers: this.headers(),
        withCredentials: true,
      }),
    );
  }

  async create(payload: {
    name: string;
    namespace: string;
    targetNamespaces: string[];
    ttlSeconds: number;
    permissions: Permission[];
  }): Promise<IssuedToken> {
    return firstValueFrom(
      this.http.post<IssuedToken>(`${this.baseUrl}/tokens`, payload, {
        headers: this.headers(),
        withCredentials: true,
      }),
    );
  }

  async update(
    identity: Identity,
    targetNamespaces: string[],
    permissions: Permission[],
  ): Promise<Identity> {
    return firstValueFrom(
      this.http.put<Identity>(
        `${this.baseUrl}/tokens/${identity.namespace}/${identity.name}`,
        { targetNamespaces, permissions },
        { headers: this.headers(), withCredentials: true },
      ),
    );
  }

  async remove(identity: Identity): Promise<void> {
    await firstValueFrom(
      this.http.delete<void>(`${this.baseUrl}/tokens/${identity.namespace}/${identity.name}`, {
        headers: this.headers(),
        withCredentials: true,
      }),
    );
  }

  async issue(identity: Identity, ttlSeconds: number): Promise<IssuedToken> {
    return firstValueFrom(
      this.http.post<IssuedToken>(
        `${this.baseUrl}/tokens/${identity.namespace}/${identity.name}/issue`,
        { ttlSeconds },
        { headers: this.headers(), withCredentials: true },
      ),
    );
  }

  private headers(): HttpHeaders {
    const token = this.adminToken();
    return token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : new HttpHeaders();
  }
}
