import { Component, inject, signal } from '@angular/core';

import { DevicesService } from '../core/devices.service';
import { StatusService } from '../core/status.service';
import { Device } from '../core/models';

@Component({
  selector: 'app-devices',
  imports: [],
  templateUrl: './devices.component.html',
  styleUrl: './devices.component.scss',
})
export class DevicesComponent {
  private readonly devicesService = inject(DevicesService);
  private readonly status = inject(StatusService);

  readonly devices = signal<Device[]>([]);
  readonly loading = signal(false);

  constructor() {
    this.refresh();
  }

  refresh(): void {
    this.loading.set(true);
    this.devicesService.list().subscribe({
      next: (devices) => {
        this.devices.set(devices);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  revoke(device: Device): void {
    if (!confirm(`Revoke "${device.name}"? It will lose access immediately.`)) return;
    this.devicesService.revoke(device.public_key).subscribe({
      next: () => {
        this.status.show(`Revoked ${device.name}.`, 'ok');
        this.refresh();
      },
      error: (err) => this.status.show(`Revoke failed: ${errorText(err)}`, 'err'),
    });
  }
}

function errorText(err: unknown): string {
  if (err && typeof err === 'object' && 'error' in err && typeof (err as { error: unknown }).error === 'string') {
    return (err as { error: string }).error;
  }
  return 'request failed';
}
