import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { Identity, IssuedToken, Permission } from './models';

export interface AuthSession {
  provider: 'authentik';
  authenticated: boolean;
  user?: { name?: string; email?: string };
}

@Injectable({ providedIn: 'root' })
export class AccessApi {
  private readonly baseUrl = '/api/v1';

  constructor(private readonly http: HttpClient) {}

  async session(): Promise<AuthSession> {
    return firstValueFrom(
      this.http.get<AuthSession>('/auth/session', { withCredentials: true }),
    );
  }

  async namespaces(): Promise<string[]> {
    return firstValueFrom(
      this.http.get<string[]>(`${this.baseUrl}/namespaces`, {
        withCredentials: true,
      }),
    );
  }

  async list(): Promise<Identity[]> {
    return firstValueFrom(
      this.http.get<Identity[]>(`${this.baseUrl}/tokens`, {
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
        { withCredentials: true },
      ),
    );
  }

  async remove(identity: Identity): Promise<void> {
    await firstValueFrom(
      this.http.delete<void>(`${this.baseUrl}/tokens/${identity.namespace}/${identity.name}`, {
        withCredentials: true,
      }),
    );
  }

  async issue(identity: Identity, ttlSeconds: number): Promise<IssuedToken> {
    return firstValueFrom(
      this.http.post<IssuedToken>(
        `${this.baseUrl}/tokens/${identity.namespace}/${identity.name}/issue`,
        { ttlSeconds },
        { withCredentials: true },
      ),
    );
  }
}
