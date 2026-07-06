import { TestBed } from '@angular/core/testing';

import { ThemeService } from './theme.service';

describe('ThemeService', () => {
  beforeEach(() => {
    localStorage.removeItem('ferrum-admin-theme');
    document.documentElement.removeAttribute('data-theme');
    TestBed.configureTestingModule({});
  });

  it('defaults to dark when there is no stored preference and the system prefers dark', () => {
    spyOn(window, 'matchMedia').and.returnValue({ matches: false } as MediaQueryList);
    const service = TestBed.inject(ThemeService);
    expect(service.theme()).toBe('dark');
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
  });

  it('defaults to light when the system prefers light', () => {
    spyOn(window, 'matchMedia').and.returnValue({ matches: true } as MediaQueryList);
    const service = TestBed.inject(ThemeService);
    expect(service.theme()).toBe('light');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
  });

  it('prefers a stored theme over the system preference', () => {
    localStorage.setItem('ferrum-admin-theme', 'light');
    spyOn(window, 'matchMedia').and.returnValue({ matches: false } as MediaQueryList);
    const service = TestBed.inject(ThemeService);
    expect(service.theme()).toBe('light');
  });

  it('toggle flips the theme, persists it, and updates the DOM attribute', () => {
    localStorage.setItem('ferrum-admin-theme', 'dark');
    const service = TestBed.inject(ThemeService);

    service.toggle();
    expect(service.theme()).toBe('light');
    expect(localStorage.getItem('ferrum-admin-theme')).toBe('light');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');

    service.toggle();
    expect(service.theme()).toBe('dark');
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
  });
});
