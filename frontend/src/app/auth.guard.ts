import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AccessApi } from './access-api';

export const authGuard: CanActivateFn = async (route, state) => {
  const api = inject(AccessApi);
  const router = inject(Router);

  try {
    const session = await api.session();
    if (session.authenticated) return true;
  } catch {
    // A rota de login tratará tanto a ausência quanto a expiração da sessão.
  }

  sessionStorage.setItem('kubeaccess_return_url', state.url);
  return router.createUrlTree(['/login']);
};
