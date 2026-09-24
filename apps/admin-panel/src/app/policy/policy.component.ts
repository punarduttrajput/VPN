import { Component, computed, inject, signal } from '@angular/core';
import { FormBuilder, FormControl, FormGroup, ReactiveFormsModule } from '@angular/forms';

import { PolicyService } from '../core/policy.service';
import { StatusService } from '../core/status.service';
import { Policy, PolicyRule } from '../core/models';

type RuleGroup = FormGroup<{ src: FormControl<string>; dst: FormControl<string> }>;

@Component({
  selector: 'app-policy',
  imports: [ReactiveFormsModule],
  templateUrl: './policy.component.html',
  styleUrl: './policy.component.scss',
})
export class PolicyComponent {
  private readonly policyService = inject(PolicyService);
  private readonly status = inject(StatusService);
  private readonly fb = inject(FormBuilder);

  readonly loading = signal(false);
  readonly saving = signal(false);
  /**
   * True only while the form holds the policy most recently fetched from the
   * coordinator. Until then the form is empty (allow_all off, no rules), and
   * saving it would silently replace the live policy with deny-all.
   */
  readonly loaded = signal(false);
  readonly loadError = signal<string | null>(null);
  readonly canSave = computed(() => this.loaded() && !this.loading() && !this.saving());
  readonly allowAll = this.fb.control(false);
  readonly rules = this.fb.array<RuleGroup>([]);

  constructor() {
    this.refresh();
  }

  get ruleGroups(): RuleGroup[] {
    return this.rules.controls as RuleGroup[];
  }

  refresh(): void {
    this.loading.set(true);
    this.policyService.get().subscribe({
      next: (policy) => {
        this.render(policy);
        this.loaded.set(true);
        this.loadError.set(null);
        this.loading.set(false);
      },
      error: (err) => {
        // Whatever the form holds is no longer known to match the coordinator,
        // so it must not be saveable (see `loaded`).
        this.loaded.set(false);
        this.loadError.set(errorText(err));
        this.loading.set(false);
        this.status.show(`Failed to load the policy: ${errorText(err)}`, 'err');
      },
    });
  }

  addRule(): void {
    this.rules.push(this.ruleGroup({ src: [], dst: [] }));
  }

  removeRule(index: number): void {
    this.rules.removeAt(index);
  }

  save(): void {
    if (!this.canSave()) return;
    const policy: Policy = {
      allow_all: Boolean(this.allowAll.value),
      rules: this.ruleGroups.map((group) => ({
        src: splitTags(group.controls.src.value ?? ''),
        dst: splitTags(group.controls.dst.value ?? ''),
      })),
    };
    this.saving.set(true);
    this.policyService.save(policy).subscribe({
      next: () => {
        this.saving.set(false);
        this.status.show('Policy saved.', 'ok');
        this.refresh();
      },
      error: (err) => {
        this.saving.set(false);
        this.status.show(`Save failed: ${errorText(err)}`, 'err');
      },
    });
  }

  private render(policy: Policy): void {
    this.allowAll.setValue(Boolean(policy.allow_all));
    this.rules.clear();
    for (const rule of policy.rules ?? []) {
      this.rules.push(this.ruleGroup(rule));
    }
  }

  private ruleGroup(rule: PolicyRule): RuleGroup {
    return new FormGroup({
      src: new FormControl((rule.src ?? []).join(', '), { nonNullable: true }),
      dst: new FormControl((rule.dst ?? []).join(', '), { nonNullable: true }),
    });
  }
}

function splitTags(value: string): string[] {
  return value
    .split(',')
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

function errorText(err: unknown): string {
  if (err && typeof err === 'object' && 'error' in err && typeof (err as { error: unknown }).error === 'string') {
    return (err as { error: string }).error;
  }
  return 'request failed';
}
