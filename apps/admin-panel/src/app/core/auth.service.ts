import { Injectable, signal } from '@angular/core';

const TOKEN_KEY = 'ferrum-admin-token';

/**
 * Holds the operator-pasted OIDC bearer token in this tab's sessionStorage
 * only — never persisted to disk, never sent anywhere but the coordinator's
 * own admin API (see authInterceptor). Mirrors admin-ui/main.js's
 * getToken/setToken.
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly tokenSignal = signal(sessionStorage.getItem(TOKEN_KEY) ?? '');

  isAuthenticated(): boolean {
    return this.tokenSignal().length > 0;
  }

  token(): string {
    return this.tokenSignal();
  }

  setToken(token: string): void {
    if (token) {
      sessionStorage.setItem(TOKEN_KEY, token);
    } else {
      sessionStorage.removeItem(TOKEN_KEY);
    }
    this.tokenSignal.set(token);
  }

  signOut(): void {
    this.setToken('');
  }
}
