import { Injectable, signal } from '@angular/core';

export type StatusKind = 'ok' | 'err';

export interface StatusMessage {
  text: string;
  kind: StatusKind;
}

/** Shared success/error banner, replacing admin-ui/main.js's single #status-banner element. */
@Injectable({ providedIn: 'root' })
export class StatusService {
  readonly message = signal<StatusMessage | null>(null);

  show(text: string, kind: StatusKind): void {
    this.message.set(text ? { text, kind } : null);
  }

  clear(): void {
    this.message.set(null);
  }
}
