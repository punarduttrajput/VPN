import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of } from 'rxjs';

import { DevicesComponent } from './devices.component';
import { DevicesService } from '../core/devices.service';
import { Device } from '../core/models';

describe('DevicesComponent', () => {
  let component: DevicesComponent;
  let fixture: ComponentFixture<DevicesComponent>;
  let devicesService: jasmine.SpyObj<DevicesService>;

  const device: Device = {
    public_key: 'AAA',
    name: 'laptop',
    endpoint: '1.1.1.1:51820',
    tunnel_ip: '10.8.0.2',
    tags: ['dev'],
    candidates: [],
  };

  beforeEach(async () => {
    devicesService = jasmine.createSpyObj<DevicesService>('DevicesService', ['list', 'revoke']);
    devicesService.list.and.returnValue(of([device]));
    devicesService.revoke.and.returnValue(of(void 0));

    await TestBed.configureTestingModule({
      imports: [DevicesComponent],
      providers: [{ provide: DevicesService, useValue: devicesService }],
    }).compileComponents();

    fixture = TestBed.createComponent(DevicesComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('loads devices on init', () => {
    expect(component.devices()).toEqual([device]);
  });

  it('revoke does nothing without confirmation', () => {
    spyOn(window, 'confirm').and.returnValue(false);
    component.revoke(device);
    expect(devicesService.revoke).not.toHaveBeenCalled();
  });

  it('revoke calls the service and refreshes after confirmation', () => {
    spyOn(window, 'confirm').and.returnValue(true);
    component.revoke(device);
    expect(devicesService.revoke).toHaveBeenCalledWith('AAA');
    expect(devicesService.list).toHaveBeenCalledTimes(2);
  });
});
