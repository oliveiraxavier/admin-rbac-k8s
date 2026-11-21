import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { AccessApi } from './access-api';
import { Identity } from './models';

describe('AccessApi', () => {
  let api: AccessApi;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [AccessApi, provideHttpClient(), provideHttpClientTesting()],
    });
    api = TestBed.inject(AccessApi);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    http.verify();
  });

  it('loads the session and workspace data', async () => {
    const sessionPromise = api.session();
    const sessionRequest = http.expectOne('/auth/session');
    expect(sessionRequest.request.withCredentials).toBe(true);
    sessionRequest.flush({ provider: 'authentik', authenticated: true, user: { email: 'admin@example.com' } });
    await expect(sessionPromise).resolves.toMatchObject({ provider: 'authentik' });

    api.connect('secret');
    const namespacesPromise = api.namespaces();
    const namespacesRequest = http.expectOne('/api/v1/namespaces');
    expect(namespacesRequest.request.headers.get('Authorization')).toBe('Bearer secret');
    namespacesRequest.flush(['default', 'apps']);
    await expect(namespacesPromise).resolves.toEqual(['default', 'apps']);
  });

  it('creates an identity and sends the payload', async () => {
    api.connect('secret');
    const identity: Identity = {
      name: 'reader',
      namespace: 'apps',
      namespaces: ['apps'],
      createdAt: '2026-11-21T00:00:00Z',
      permissions: [{ apiGroup: '', resource: 'pods', verbs: ['get'] }],
    };
    const issued = { identity, token: 'jwt-token', expiresAt: '2026-11-22T00:00:00Z' };
    const promise = api.create({
      name: 'reader',
      namespace: 'apps',
      targetNamespaces: ['apps'],
      ttlSeconds: 28800,
      permissions: [{ apiGroup: '', resource: 'pods', verbs: ['get'] }],
    });
    const request = http.expectOne('/api/v1/tokens');
    expect(request.request.method).toBe('POST');
    expect(request.request.body.name).toBe('reader');
    request.flush(issued);

    await expect(promise).resolves.toEqual(issued);
  });

  it('removes an identity through its namespace and name', async () => {
    const identity: Identity = {
      name: 'reader',
      namespace: 'apps',
      namespaces: ['apps'],
      createdAt: '2026-11-21T00:00:00Z',
      permissions: [],
    };
    const promise = api.remove(identity);
    const request = http.expectOne('/api/v1/tokens/apps/reader');
    expect(request.request.method).toBe('DELETE');
    request.flush(null);

    await expect(promise).resolves.toBeUndefined();
  });
});
