import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Router, provideRouter } from '@angular/router';

import { authInterceptor } from './auth.interceptor';
import { AuthService } from './auth.service';

describe('authInterceptor', () => {
  let http: HttpClient;
  let httpMock: HttpTestingController;
  let auth: AuthService;
  let router: Router;

  beforeEach(() => {
    sessionStorage.clear();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    });
    http = TestBed.inject(HttpClient);
    httpMock = TestBed.inject(HttpTestingController);
    auth = TestBed.inject(AuthService);
    router = TestBed.inject(Router);
  });

  afterEach(() => {
    httpMock.verify();
    sessionStorage.clear();
  });

  it('attaches the stored token as a bearer header', () => {
    auth.setToken('secret-token');

    http.get('/api/devices').subscribe();
    const req = httpMock.expectOne('/api/devices');
    expect(req.request.headers.get('Authorization')).toBe('Bearer secret-token');
    req.flush([]);
  });

  it('clears the token and redirects to /login on a 401', () => {
    auth.setToken('secret-token');
    const navigateSpy = spyOn(router, 'navigateByUrl');

    http.get('/api/devices').subscribe({ error: () => {} });
    const req = httpMock.expectOne('/api/devices');
    req.flush('missing bearer token', { status: 401, statusText: 'Unauthorized' });

    expect(auth.isAuthenticated()).toBe(false);
    expect(navigateSpy).toHaveBeenCalledWith('/login');
  });

  it('clears the token and redirects to /login on a 403', () => {
    auth.setToken('secret-token');
    const navigateSpy = spyOn(router, 'navigateByUrl');

    http.get('/api/devices').subscribe({ error: () => {} });
    const req = httpMock.expectOne('/api/devices');
    req.flush('token lacks the admin tag', { status: 403, statusText: 'Forbidden' });

    expect(auth.isAuthenticated()).toBe(false);
    expect(navigateSpy).toHaveBeenCalledWith('/login');
  });
});
