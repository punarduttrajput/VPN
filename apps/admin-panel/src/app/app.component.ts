import { Component, inject } from '@angular/core';
import { RouterOutlet } from '@angular/router';

import { ThemeService } from './core/theme.service';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss',
})
export class AppComponent {
  // Not read anywhere in this component — injecting it here just forces
  // ThemeService's constructor (which applies the stored/system theme to
  // <html>) to run at bootstrap, before any route renders. Without this,
  // it was only created lazily when ShellComponent first loaded, so the
  // unauthenticated /login route always fell back to :root's un-themed
  // (dark) defaults regardless of the user's actual preference.
  private readonly theme = inject(ThemeService);
}
