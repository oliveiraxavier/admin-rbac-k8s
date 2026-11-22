import { Component, OnInit, signal } from '@angular/core';
import { Router } from '@angular/router';
import { AccessApi } from './access-api';

@Component({
  selector: 'app-login',
  template: `
    <main class="login-screen">
      <section class="login-card" aria-labelledby="login-title">
        <div class="login-brand" aria-hidden="true">
          <span class="brand-mark"><i></i><i></i><i></i></span>
          <span class="brand-name">kube<span>access</span></span>
        </div>
        <div class="login-copy">
          <div class="eyebrow"><span class="eyebrow-mark"></span> KUBERNETES ACCESS CONTROL</div>
          <h1 id="login-title">Bem-vindo</h1>
          <p>Entre com sua conta administrativa para gerenciar identidades e permissões RBAC.</p>
        </div>
        @if (checking()) {
          <button class="login-button" type="button" disabled>Verificando sessão...</button>
        } @else {
          <button class="login-button" type="button" (click)="login()">
            Entrar com Authentik <span aria-hidden="true">↗</span>
          </button>
        }
        @if (error()) {
          <p class="login-error" role="alert">{{ error() }}</p>
        }
      </section>
    </main>
  `,
  styles: `
    :host { display: block; min-height: 100dvh; }
    .login-screen { display: grid; min-height: 100dvh; place-items: center; padding: 24px; background: radial-gradient(circle at 75% 20%, #ede7f2 0, transparent 28%), var(--paper); }
    .login-card { width: min(420px, 100%); padding: 38px; border: 1px solid var(--line); border-radius: 10px; background: #fff; box-shadow: 0 24px 70px #26372f14; }
    .login-brand { display: flex; align-items: center; gap: 11px; }
    .brand-mark { display: grid; grid-template-columns: repeat(3, 5px); align-items: center; gap: 3px; width: 30px; height: 30px; padding: 7px; border: 1px solid #9370a7; border-radius: 9px; background: var(--forest-dark); transform: rotate(-8deg); }
    .brand-mark i { width: 4px; background: var(--lime); border-radius: 5px; }
    .brand-mark i:nth-child(1) { height: 8px; } .brand-mark i:nth-child(2) { height: 14px; } .brand-mark i:nth-child(3) { height: 10px; }
    .brand-name { color: var(--forest-dark); font-size: 17px; font-weight: 700; }
    .brand-name span { color: #9a78aa; font-weight: 400; }
    .login-copy { margin: 42px 0 30px; }
    .eyebrow { display: flex; align-items: center; gap: 8px; color: #71817a; font: 500 9px var(--mono); }
    .eyebrow-mark { width: 7px; height: 7px; border-radius: 2px; background: var(--coral); transform: rotate(45deg); }
    h1 { margin: 12px 0 9px; color: #22312c; font-size: 34px; }
    p { color: #7b8782; font-size: 13px; line-height: 1.65; }
    .login-button { display: flex; align-items: center; justify-content: space-between; width: 100%; min-height: 48px; padding: 0 17px; border: 1px solid var(--forest); border-radius: 5px; color: #fff; background: var(--forest); font-size: 12px; font-weight: 600; }
    .login-button:hover:not(:disabled) { background: var(--forest-dark); }
    .login-button:disabled { cursor: wait; opacity: .65; }
    .login-button span { color: var(--lime); font-size: 16px; }
    .login-error { margin: 13px 0 0; color: #a24e3b; font-size: 11px; }
  `,
})
export class LoginComponent implements OnInit {
  protected readonly checking = signal(true);
  protected readonly error = signal('');

  constructor(
    private readonly api: AccessApi,
    private readonly router: Router,
  ) {}

  async ngOnInit(): Promise<void> {
    try {
      const session = await this.api.session();
      if (session.authenticated) {
        const returnUrl = sessionStorage.getItem('kubeaccess_return_url') || '/';
        sessionStorage.removeItem('kubeaccess_return_url');
        await this.router.navigateByUrl(returnUrl);
        return;
      }
    } catch {
      this.error.set('Não foi possível verificar a sessão. Tente entrar novamente.');
    } finally {
      this.checking.set(false);
    }
  }

  protected login(): void {
    const returnUrl = sessionStorage.getItem('kubeaccess_return_url') || '/';
    const safeReturnUrl = returnUrl.startsWith('/') && !returnUrl.startsWith('//') ? returnUrl : '/';
    window.location.assign(`/auth/login?return_to=${encodeURIComponent(safeReturnUrl)}`);
  }
}
