import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';

import { DashboardComponent } from './dashboard.component';
import { DevicesService } from '../core/devices.service';
import { PolicyService } from '../core/policy.service';
import { Device, Policy } from '../core/models';

describe('DashboardComponent', () => {
  let component: DashboardComponent;
  let fixture: ComponentFixture<DashboardComponent>;
  let devicesService: jasmine.SpyObj<DevicesService>;
  let policyService: jasmine.SpyObj<PolicyService>;

  const devices: Device[] = [
    {
      public_key: 'AAA',
      name: 'laptop',
      endpoint: '1.1.1.1:51820',
      tunnel_ip: '10.8.0.2',
      tags: ['dev', 'admin'],
      candidates: [],
    },
    {
      public_key: 'BBB',
      name: 'phone',
      endpoint: null,
      tunnel_ip: '10.8.0.3',
      tags: ['dev'],
      candidates: [],
    },
  ];
  const policy: Policy = { allow_all: false, rules: [{ src: ['dev'], dst: ['server'] }] };

  beforeEach(async () => {
    devicesService = jasmine.createSpyObj<DevicesService>('DevicesService', ['list', 'revoke']);
    policyService = jasmine.createSpyObj<PolicyService>('PolicyService', ['get', 'save']);
    devicesService.list.and.returnValue(of(devices));
    policyService.get.and.returnValue(of(policy));

    await TestBed.configureTestingModule({
      imports: [DashboardComponent],
      providers: [
        provideRouter([]),
        { provide: DevicesService, useValue: devicesService },
        { provide: PolicyService, useValue: policyService },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(DashboardComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('derives device/tag/pending counts from the loaded devices', () => {
    expect(component.deviceCount()).toBe(2);
    expect(component.pendingCount()).toBe(1); // "phone" has no endpoint
    expect(component.tagCount()).toBe(2); // "dev" + "admin"
  });

  it('labels the policy by rule count when not allow-all', () => {
    expect(component.policyLabel()).toBe('1 rule');
  });

  it('labels the policy as "Allow all" when it is', () => {
    policyService.get.and.returnValue(of({ allow_all: true, rules: [] }));
    component.refresh();
    expect(component.policyLabel()).toBe('Allow all');
  });

  it('shows only the first 5 devices in the recent-devices preview', () => {
    const many = Array.from({ length: 8 }, (_, i) => ({ ...devices[0], public_key: `key-${i}` }));
    devicesService.list.and.returnValue(of(many));
    component.refresh();
    expect(component.recentDevices().length).toBe(5);
    expect(component.deviceCount()).toBe(8);
  });
});
