import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import { PolicyService } from './policy.service';
import { Policy } from './models';

describe('PolicyService', () => {
  let service: PolicyService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(PolicyService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('gets the policy from GET /api/policy', () => {
    const policy: Policy = { allow_all: false, rules: [{ src: ['dev'], dst: ['server'] }] };

    service.get().subscribe((result) => expect(result).toEqual(policy));
    const req = httpMock.expectOne('/api/policy');
    expect(req.request.method).toBe('GET');
    req.flush(policy);
  });

  it('saves the policy via PUT /api/policy', () => {
    const policy: Policy = { allow_all: true, rules: [] };

    service.save(policy).subscribe();
    const req = httpMock.expectOne('/api/policy');
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual(policy);
    req.flush(null, { status: 204, statusText: 'No Content' });
  });
});
