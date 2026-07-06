import { inject } from '@angular/core';
import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';

import { AuthService } from './auth.service';
import { StatusService } from './status.service';

/**
 * Attaches `Authorization: Bearer <token>` to every request and, on a
 * 401/403, treats it as "the token isn't good enough" — clears it and
 * bounces back to /login — rather than leaving a broken panel up. Mirrors
 * admin-ui/main.js's `api()` wrapper.
 */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(AuthService);
  const router = inject(Router);
  const status = inject(StatusService);

  const token = auth.token();
  const authorized = token ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }) : req;

  return next(authorized).pipe(
    catchError((err: unknown) => {
      if (err instanceof HttpErrorResponse && (err.status === 401 || err.status === 403)) {
        auth.signOut();
        status.show(errorMessage(err) || 'token rejected — sign in again', 'err');
        router.navigateByUrl('/login');
      }
      return throwError(() => err);
    }),
  );
};

function errorMessage(err: HttpErrorResponse): string {
  if (typeof err.error === 'string') return err.error;
  return '';
}
