import { Routes } from '@angular/router';
import { App } from './app';
import { authGuard } from './auth.guard';
import { LoginComponent } from './login.component';

export const routes: Routes = [
  { path: 'login', component: LoginComponent },
  { path: '', component: App, canActivate: [authGuard], pathMatch: 'full' },
  { path: '**', redirectTo: '' },
];
