import { Routes } from '@angular/router';

import { authGuard } from './core/auth.guard';

export const routes: Routes = [
  {
    path: 'login',
    loadComponent: () => import('./login/login.component').then((m) => m.LoginComponent),
  },
  {
    path: '',
    loadComponent: () => import('./shell/shell.component').then((m) => m.ShellComponent),
    canActivate: [authGuard],
    children: [
      { path: '', redirectTo: 'devices', pathMatch: 'full' },
      {
        path: 'devices',
        loadComponent: () => import('./devices/devices.component').then((m) => m.DevicesComponent),
      },
      {
        path: 'policy',
        loadComponent: () => import('./policy/policy.component').then((m) => m.PolicyComponent),
      },
    ],
  },
  { path: '**', redirectTo: '' },
];
