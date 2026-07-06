import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

import { Policy } from './models';

@Injectable({ providedIn: 'root' })
export class PolicyService {
  private readonly http = inject(HttpClient);

  get(): Observable<Policy> {
    return this.http.get<Policy>('/api/policy');
  }

  save(policy: Policy): Observable<void> {
    return this.http.put<void>('/api/policy', policy);
  }
}
