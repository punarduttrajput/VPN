import { Injectable, signal } from '@angular/core';

export type Theme = 'light' | 'dark';

const STORAGE_KEY = 'ferrum-admin-theme';

/**
 * Light/dark theme preference — persisted to `localStorage` (a UI
 * preference, not a secret, unlike the admin token which stays in
 * `sessionStorage` — see `AuthService`). Defaults to the OS/browser's
 * `prefers-color-scheme` when nothing has been chosen yet, and applies by
 * setting `data-theme` on `<html>`, which `styles.scss`'s variable
 * overrides key off of.
 */
@Injectable({ providedIn: 'root' })
export class ThemeService {
  private readonly themeSignal = signal<Theme>(this.initialTheme());

  readonly theme = this.themeSignal.asReadonly();

  constructor() {
    this.apply(this.themeSignal());
  }

  toggle(): void {
    this.set(this.themeSignal() === 'dark' ? 'light' : 'dark');
  }

  set(theme: Theme): void {
    localStorage.setItem(STORAGE_KEY, theme);
    this.themeSignal.set(theme);
    this.apply(theme);
  }

  private apply(theme: Theme): void {
    document.documentElement.setAttribute('data-theme', theme);
  }

  private initialTheme(): Theme {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'light' || stored === 'dark') {
      return stored;
    }
    const prefersLight = window.matchMedia?.('(prefers-color-scheme: light)').matches;
    return prefersLight ? 'light' : 'dark';
  }
}
