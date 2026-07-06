import { Component, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { forkJoin } from 'rxjs';

import { DevicesService } from '../core/devices.service';
import { PolicyService } from '../core/policy.service';
import { StatusService } from '../core/status.service';
import { Device, Policy } from '../core/models';

@Component({
  selector: 'app-dashboard',
  imports: [RouterLink],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss',
})
export class DashboardComponent {
  private readonly devicesService = inject(DevicesService);
  private readonly policyService = inject(PolicyService);
  private readonly status = inject(StatusService);

  readonly loading = signal(false);
  readonly devices = signal<Device[]>([]);
  readonly policy = signal<Policy | null>(null);

  readonly deviceCount = computed(() => this.devices().length);
  readonly pendingCount = computed(() => this.devices().filter((d) => !d.endpoint).length);
  readonly tagCount = computed(() => new Set(this.devices().flatMap((d) => d.tags)).size);
  readonly recentDevices = computed(() => this.devices().slice(0, 5));

  readonly policyLabel = computed(() => {
    const policy = this.policy();
    if (!policy) return '—';
    if (policy.allow_all) return 'Allow all';
    const n = policy.rules.length;
    return `${n} rule${n === 1 ? '' : 's'}`;
  });

  constructor() {
    this.refresh();
  }

  refresh(): void {
    this.loading.set(true);
    forkJoin({ devices: this.devicesService.list(), policy: this.policyService.get() }).subscribe({
      next: ({ devices, policy }) => {
        this.devices.set(devices);
        this.policy.set(policy);
        this.loading.set(false);
      },
      error: (err) => {
        this.loading.set(false);
        this.status.show(`Failed to load dashboard: ${errorText(err)}`, 'err');
      },
    });
  }
}

function errorText(err: unknown): string {
  if (err && typeof err === 'object' && 'error' in err && typeof (err as { error: unknown }).error === 'string') {
    return (err as { error: string }).error;
  }
  return 'request failed';
}
