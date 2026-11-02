import { Injectable, signal } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

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

@Injectable({ providedIn: 'root' })
export class AccessApi {
  private readonly baseUrl = '/api/v1';
  private readonly adminToken = signal<string | null>(null);

  constructor(private readonly http: HttpClient) {}

  connect(token: string): void {
    this.adminToken.set(token);
  }

  disconnect(): void {
    this.adminToken.set(null);
  }

  async namespaces(): Promise<string[]> {
    return firstValueFrom(
      this.http.get<string[]>(`${this.baseUrl}/namespaces`, { headers: this.headers() }),
    );
  }

  async list(): Promise<Identity[]> {
    return firstValueFrom(
      this.http.get<Identity[]>(`${this.baseUrl}/tokens`, { headers: this.headers() }),
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
      this.http.post<IssuedToken>(`${this.baseUrl}/tokens`, payload, { headers: this.headers() }),
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
        { headers: this.headers() },
      ),
    );
  }

  async remove(identity: Identity): Promise<void> {
    await firstValueFrom(
      this.http.delete<void>(`${this.baseUrl}/tokens/${identity.namespace}/${identity.name}`, {
        headers: this.headers(),
      }),
    );
  }

  async issue(identity: Identity, ttlSeconds: number): Promise<IssuedToken> {
    return firstValueFrom(
      this.http.post<IssuedToken>(
        `${this.baseUrl}/tokens/${identity.namespace}/${identity.name}/issue`,
        { ttlSeconds },
        { headers: this.headers() },
      ),
    );
  }

  private headers(): HttpHeaders {
    const token = this.adminToken();
    if (!token) {
      throw new Error('Conecte-se à API para continuar.');
    }
    return new HttpHeaders({ Authorization: `Bearer ${token}` });
  }
}
