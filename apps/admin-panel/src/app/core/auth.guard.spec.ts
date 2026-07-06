import { TestBed } from '@angular/core/testing';
import { CanActivateFn, Router, UrlTree } from '@angular/router';

import { authGuard } from './auth.guard';
import { AuthService } from './auth.service';

describe('authGuard', () => {
  const executeGuard: CanActivateFn = (...guardParameters) =>
    TestBed.runInInjectionContext(() => authGuard(...guardParameters));

  afterEach(() => sessionStorage.clear());

  it('redirects to /login when no token is stored', () => {
    sessionStorage.clear();
    TestBed.configureTestingModule({});
    const result = executeGuard({} as never, {} as never);
    expect((result as UrlTree).toString()).toContain('/login');
  });

  it('allows navigation when a token is stored', () => {
    TestBed.configureTestingModule({});
    const auth = TestBed.inject(AuthService);
    auth.setToken('a-token');

    const result = executeGuard({} as never, {} as never);
    expect(result).toBe(true);
  });
});
