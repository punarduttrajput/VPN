import { ComponentFixture, TestBed, discardPeriodicTasks, fakeAsync, tick } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { Subject, of, throwError } from 'rxjs';

import { DashboardComponent, REFRESH_MS } from './dashboard.component';
import { DevicesService } from '../core/devices.service';
import { PolicyService } from '../core/policy.service';
import { StatusService } from '../core/status.service';
import { Device, Policy } from '../core/models';

describe('DashboardComponent', () => {
  let component: DashboardComponent;
  let fixture: ComponentFixture<DashboardComponent>;
  let devicesService: jasmine.SpyObj<DevicesService>;
  let policyService: jasmine.SpyObj<PolicyService>;
  let status: StatusService;

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
  const many = (n: number) => Array.from({ length: n }, (_, i) => ({ ...devices[0], public_key: `key-${i}` }));
  const httpError = (error: string) => throwError(() => ({ error }));

  /** The rendered page text. */
  const text = () => (fixture.nativeElement as HTMLElement).textContent ?? '';

  function create(): void {
    fixture = TestBed.createComponent(DashboardComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  }

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
    status = TestBed.inject(StatusService);
    spyOn(status, 'show').and.callThrough();
  });

  afterEach(() => fixture?.destroy());

  describe('with both sources loading', () => {
    beforeEach(create);

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
      devicesService.list.and.returnValue(of(many(8)));
      component.refresh();
      expect(component.recentDevices().length).toBe(5);
      expect(component.deviceCount()).toBe(8);
    });

    // DASH-008: the "view all" threshold.
    it('offers "view all" only when there are more devices than the preview shows', () => {
      devicesService.list.and.returnValue(of(many(8)));
      component.refresh();
      fixture.detectChanges();
      expect(text()).toContain('view all 8 devices');

      devicesService.list.and.returnValue(of(many(5)));
      component.refresh();
      fixture.detectChanges();
      expect(text()).not.toContain('view all');
    });

    it('raises no banner when everything loads', () => {
      expect(status.show).not.toHaveBeenCalled();
    });
  });

  // DASH-002: one source failing keeps the other's data.
  describe('when one source fails', () => {
    it('still renders the devices when the policy fails', () => {
      policyService.get.and.returnValue(httpError('policy store down'));
      create();
      expect(component.deviceCount()).toBe(2);
      expect(component.policyError()).toBe('policy store down');
      expect(component.policyLabel()).toBe('—');
      expect(text()).toContain('laptop');
      expect(text()).toContain("couldn't load");
      expect(status.show).toHaveBeenCalledOnceWith('Failed to load policy: policy store down', 'err');
    });

    it('still renders the policy when the devices fail', () => {
      devicesService.list.and.returnValue(httpError('registry down'));
      create();
      expect(component.policyLabel()).toBe('1 rule');
      expect(component.deviceCount()).toBeNull();
      expect(text()).toContain("Couldn't load devices: registry down");
      expect(text()).not.toContain('No devices registered.');
      expect(status.show).toHaveBeenCalledOnceWith('Failed to load devices: registry down', 'err');
    });

    it('reports both when both fail', () => {
      devicesService.list.and.returnValue(httpError('a'));
      policyService.get.and.returnValue(httpError('b'));
      create();
      expect(status.show).toHaveBeenCalledOnceWith('Failed to load devices: a; policy: b', 'err');
      expect(component.updatedAt()).toBeNull();
    });

    it('keeps the last data when a refresh fails, and says it is stale', () => {
      create();
      devicesService.list.and.returnValue(httpError('flaky'));
      component.refresh();
      fixture.detectChanges();
      expect(component.deviceCount()).toBe(2);
      expect(text()).toContain("couldn't refresh");
      expect(text()).toContain('laptop');
    });

    it('raises the banner once for a source that stays down, and recovers', () => {
      policyService.get.and.returnValue(httpError('down'));
      create();
      component.refresh();
      component.refresh();
      expect(status.show).toHaveBeenCalledTimes(1);

      policyService.get.and.returnValue(of(policy));
      component.refresh();
      expect(component.policyError()).toBeNull();
      expect(component.policyLabel()).toBe('1 rule');
    });
  });

  // DASH-003: loading and empty look different.
  describe('loading and empty states', () => {
    it('shows a loading state, not an empty one, while the devices are in flight', () => {
      const pending = new Subject<Device[]>();
      devicesService.list.and.returnValue(pending);
      create();
      expect(component.loading()).toBeTrue();
      expect(component.deviceCount()).toBeNull();
      expect(text()).toContain('Loading devices…');
      expect(text()).not.toContain('No devices registered.');
      expect(text()).not.toMatch(/\b0\b/);

      pending.next([]);
      pending.complete();
      fixture.detectChanges();
      expect(component.loading()).toBeFalse();
      expect(text()).toContain('No devices registered.');
      expect(text()).not.toContain('Loading devices…');
      expect(component.deviceCount()).toBe(0);
    });

    it('keeps showing the loaded devices during a later refresh', () => {
      create();
      const pending = new Subject<Device[]>();
      devicesService.list.and.returnValue(pending);
      component.refresh();
      fixture.detectChanges();
      expect(component.loading()).toBeTrue();
      expect(text()).toContain('laptop');
      expect(text()).not.toContain('Loading devices…');
      pending.next(devices);
      pending.complete();
    });

    it('ignores a refresh while one is in flight', () => {
      const pending = new Subject<Device[]>();
      devicesService.list.and.returnValue(pending);
      create();
      component.refresh();
      expect(devicesService.list).toHaveBeenCalledTimes(1);
      pending.next(devices);
      pending.complete();
    });
  });

  // DASH-009: freshness.
  describe('last updated', () => {
    beforeEach(create);

    it('says how long ago the data loaded', () => {
      const at = component.updatedAt()!;
      expect(at).not.toBeNull();
      expect(component.updatedLabel()).toBe('Updated just now');
      component.now.set(at + 42_000);
      expect(component.updatedLabel()).toBe('Updated 42 s ago');
      component.now.set(at + 185_000);
      expect(component.updatedLabel()).toBe('Updated 3 min ago');
    });

    it('shows the label next to Refresh', () => {
      expect(text()).toContain('Updated just now');
    });
  });

  // DASH-001: auto-refresh while visible, paused while hidden.
  describe('auto-refresh', () => {
    let hidden = false;

    beforeEach(() => {
      hidden = false;
      Object.defineProperty(document, 'hidden', { configurable: true, get: () => hidden });
    });

    afterEach(() => {
      delete (document as unknown as { hidden?: boolean }).hidden;
    });

    const setHidden = (value: boolean) => {
      hidden = value;
      document.dispatchEvent(new Event('visibilitychange'));
    };

    it('reloads on the interval', fakeAsync(() => {
      create();
      expect(devicesService.list).toHaveBeenCalledTimes(1);
      tick(REFRESH_MS);
      expect(devicesService.list).toHaveBeenCalledTimes(2);
      tick(REFRESH_MS);
      expect(devicesService.list).toHaveBeenCalledTimes(3);
      fixture.destroy();
      discardPeriodicTasks();
    }));

    it('pauses while the page is hidden and reloads as soon as it is visible again', fakeAsync(() => {
      create();
      setHidden(true);
      tick(REFRESH_MS * 3);
      expect(devicesService.list).toHaveBeenCalledTimes(1);

      setHidden(false);
      tick(0);
      expect(devicesService.list).toHaveBeenCalledTimes(2);
      tick(REFRESH_MS);
      expect(devicesService.list).toHaveBeenCalledTimes(3);
      fixture.destroy();
      discardPeriodicTasks();
    }));

    it('stops when the dashboard is left', fakeAsync(() => {
      create();
      fixture.destroy();
      tick(REFRESH_MS * 3);
      expect(devicesService.list).toHaveBeenCalledTimes(1);
      discardPeriodicTasks();
    }));
  });
});
