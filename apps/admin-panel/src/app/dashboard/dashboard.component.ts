import { DOCUMENT } from '@angular/common';
import { Component, WritableSignal, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import {
  EMPTY,
  Observable,
  catchError,
  distinctUntilChanged,
  forkJoin,
  fromEvent,
  interval,
  map,
  of,
  startWith,
  switchMap,
  timer,
} from 'rxjs';

import { DevicesService } from '../core/devices.service';
import { PolicyService } from '../core/policy.service';
import { StatusService } from '../core/status.service';
import { Device, Policy } from '../core/models';

/** How often the Dashboard reloads while it's visible (DASH-001). */
export const REFRESH_MS = 15_000;
/** How often the "Updated … ago" label is recomputed (DASH-009). */
const CLOCK_MS = 5_000;

/** One source's outcome: its value, or why it failed. */
type Settled<T> = { ok: true; value: T } | { ok: false; error: string };

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
  private readonly document = inject(DOCUMENT);

  /** A refresh is in flight. */
  readonly loading = signal(false);
  /** The last devices that loaded; `null` until the first successful load. */
  readonly devices = signal<Device[] | null>(null);
  /** The last policy that loaded; `null` until the first successful load. */
  readonly policy = signal<Policy | null>(null);
  /** Why the latest devices load failed, or `null` if it didn't. */
  readonly devicesError = signal<string | null>(null);
  /** Why the latest policy load failed, or `null` if it didn't. */
  readonly policyError = signal<string | null>(null);
  /** When the last refresh in which anything loaded finished (ms since epoch). */
  readonly updatedAt = signal<number | null>(null);
  /** The current time, ticking every few seconds for the freshness label. */
  readonly now = signal(Date.now());

  readonly deviceCount = computed(() => this.devices()?.length ?? null);
  readonly pendingCount = computed(() => this.devices()?.filter((d) => !d.endpoint).length ?? null);
  readonly tagCount = computed(() => {
    const devices = this.devices();
    return devices ? new Set(devices.flatMap((d) => d.tags)).size : null;
  });
  readonly recentDevices = computed(() => (this.devices() ?? []).slice(0, 5));
  /** Loaded successfully and there are no devices: the only time "empty" is true. */
  readonly empty = computed(() => this.devices()?.length === 0);

  readonly policyLabel = computed(() => {
    const policy = this.policy();
    if (!policy) return '—';
    if (policy.allow_all) return 'Allow all';
    const n = policy.rules.length;
    return `${n} rule${n === 1 ? '' : 's'}`;
  });

  readonly updatedLabel = computed(() => {
    const at = this.updatedAt();
    if (at === null) return '';
    const secs = Math.max(0, Math.floor((this.now() - at) / 1000));
    if (secs < 5) return 'Updated just now';
    if (secs < 60) return `Updated ${secs} s ago`;
    return `Updated ${Math.floor(secs / 60)} min ago`;
  });

  constructor() {
    this.refresh();

    // Reload on an interval while the page is visible; when it becomes
    // visible again, reload at once. Leaving the route destroys the
    // component, which stops both (DASH-001).
    const visible$ = fromEvent(this.document, 'visibilitychange').pipe(
      map(() => !this.document.hidden),
      startWith(!this.document.hidden),
      distinctUntilChanged(),
    );
    visible$
      .pipe(
        switchMap((visible, i) => (visible ? timer(i === 0 ? REFRESH_MS : 0, REFRESH_MS) : EMPTY)),
        takeUntilDestroyed(),
      )
      .subscribe(() => this.refresh());

    interval(CLOCK_MS)
      .pipe(takeUntilDestroyed())
      .subscribe(() => this.now.set(Date.now()));
  }

  /**
   * Reload devices and policy. Each loads on its own (DASH-002): one failing
   * keeps the other's data, and a failed source keeps showing what it last
   * loaded, marked as not refreshed. A refresh already in flight wins.
   */
  refresh(): void {
    if (this.loading()) return;
    this.loading.set(true);
    forkJoin({
      devices: settle(this.devicesService.list()),
      policy: settle(this.policyService.get()),
    }).subscribe(({ devices, policy }) => {
      const failed: string[] = [];
      if (apply(devices, this.devices, this.devicesError)) failed.push(`devices: ${this.devicesError()}`);
      if (apply(policy, this.policy, this.policyError)) failed.push(`policy: ${this.policyError()}`);
      this.loading.set(false);
      if (devices.ok || policy.ok) {
        this.now.set(Date.now());
        this.updatedAt.set(this.now());
      }
      if (failed.length > 0) {
        this.status.show(`Failed to load ${failed.join('; ')}`, 'err');
      }
    });
  }
}

/** Never errors: maps a source's value or failure into a `Settled`. */
function settle<T>(source: Observable<T>): Observable<Settled<T>> {
  return source.pipe(
    map((value): Settled<T> => ({ ok: true, value })),
    catchError((err) => of<Settled<T>>({ ok: false, error: errorText(err) })),
  );
}

/**
 * Store one source's outcome. Returns true when this load newly failed (it
 * wasn't failing before), so a source that stays down doesn't re-raise the
 * banner on every automatic refresh.
 */
function apply<T>(
  result: Settled<T>,
  value: WritableSignal<T | null>,
  error: WritableSignal<string | null>,
): boolean {
  if (result.ok) {
    value.set(result.value);
    error.set(null);
    return false;
  }
  const newly = error() === null;
  error.set(result.error);
  return newly;
}

function errorText(err: unknown): string {
  if (err && typeof err === 'object' && 'error' in err && typeof (err as { error: unknown }).error === 'string') {
    return (err as { error: string }).error;
  }
  return 'request failed';
}
