import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

import { Device } from './models';

@Injectable({ providedIn: 'root' })
export class DevicesService {
  private readonly http = inject(HttpClient);

  list(): Observable<Device[]> {
    return this.http.get<Device[]>('/api/devices');
  }

  revoke(publicKey: string): Observable<void> {
    return this.http.post<void>('/api/devices/revoke', { public_key: publicKey });
  }
}
