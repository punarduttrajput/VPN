import { Component, inject, signal } from '@angular/core';
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
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  addRule(): void {
    this.rules.push(this.ruleGroup({ src: [], dst: [] }));
  }

  removeRule(index: number): void {
    this.rules.removeAt(index);
  }

  save(): void {
    const policy: Policy = {
      allow_all: Boolean(this.allowAll.value),
      rules: this.ruleGroups.map((group) => ({
        src: splitTags(group.controls.src.value ?? ''),
        dst: splitTags(group.controls.dst.value ?? ''),
      })),
    };
    this.policyService.save(policy).subscribe({
      next: () => {
        this.status.show('Policy saved.', 'ok');
        this.refresh();
      },
      error: (err) => this.status.show(`Save failed: ${errorText(err)}`, 'err'),
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
