import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import { DevicesService } from './devices.service';
import { Device } from './models';

describe('DevicesService', () => {
  let service: DevicesService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(DevicesService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('lists devices from GET /api/devices', () => {
    const devices: Device[] = [
      {
        public_key: 'AAA',
        name: 'laptop',
        endpoint: '1.1.1.1:51820',
        tunnel_ip: '10.8.0.2',
        tags: ['dev'],
        candidates: [],
      },
    ];

    service.list().subscribe((result) => expect(result).toEqual(devices));
    const req = httpMock.expectOne('/api/devices');
    expect(req.request.method).toBe('GET');
    req.flush(devices);
  });

  it('revokes a device via POST /api/devices/revoke', () => {
    service.revoke('AAA').subscribe();
    const req = httpMock.expectOne('/api/devices/revoke');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ public_key: 'AAA' });
    req.flush(null, { status: 204, statusText: 'No Content' });
  });
});
