import { ComponentFixture, TestBed } from '@angular/core/testing';
import { HttpErrorResponse } from '@angular/common/http';
import { Subject, of, throwError } from 'rxjs';

import { PolicyComponent } from './policy.component';
import { PolicyService } from '../core/policy.service';
import { StatusService } from '../core/status.service';
import { Policy } from '../core/models';

describe('PolicyComponent', () => {
  let component: PolicyComponent;
  let fixture: ComponentFixture<PolicyComponent>;
  let policyService: jasmine.SpyObj<PolicyService>;

  const initialPolicy: Policy = {
    allow_all: false,
    rules: [{ src: ['dev'], dst: ['server'] }],
  };

  beforeEach(async () => {
    policyService = jasmine.createSpyObj<PolicyService>('PolicyService', ['get', 'save']);
    policyService.get.and.returnValue(of(initialPolicy));
    policyService.save.and.returnValue(of(void 0));

    await TestBed.configureTestingModule({
      imports: [PolicyComponent],
      providers: [{ provide: PolicyService, useValue: policyService }],
    }).compileComponents();

    fixture = TestBed.createComponent(PolicyComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('renders the fetched policy into the form', () => {
    expect(component.allowAll.value).toBe(false);
    expect(component.ruleGroups.length).toBe(1);
    expect(component.ruleGroups[0].controls.src.value).toBe('dev');
    expect(component.ruleGroups[0].controls.dst.value).toBe('server');
  });

  it('addRule appends an empty rule row', () => {
    component.addRule();
    expect(component.ruleGroups.length).toBe(2);
    expect(component.ruleGroups[1].controls.src.value).toBe('');
  });

  it('removeRule drops the rule at the given index', () => {
    component.addRule();
    component.removeRule(0);
    expect(component.ruleGroups.length).toBe(1);
  });

  it('save splits comma-separated tags and trims whitespace', () => {
    component.ruleGroups[0].controls.src.setValue(' dev , admin ,, ');
    component.ruleGroups[0].controls.dst.setValue('server');

    component.save();

    expect(policyService.save).toHaveBeenCalledWith({
      allow_all: false,
      rules: [{ src: ['dev', 'admin'], dst: ['server'] }],
    });
  });

  const saveButton = (): HTMLButtonElement =>
    [...(fixture.nativeElement as HTMLElement).querySelectorAll('button')].find(
      (b) => b.textContent?.trim() === 'Save policy',
    ) as HTMLButtonElement;

  it('enables Save once the policy has loaded', () => {
    expect(component.canSave()).toBeTrue();
    expect(saveButton().disabled).toBeFalse();
  });

  /**
   * Regression: a failed load used to leave an empty (deny-all) form with Save
   * enabled, so one click replaced the live policy with `rules: []`.
   */
  describe('when loading the policy fails', () => {
    beforeEach(() => {
      policyService.get.and.returnValue(
        throwError(() => new HttpErrorResponse({ status: 503, error: 'coordinator busy' })),
      );
      policyService.save.calls.reset();
      component.refresh();
      fixture.detectChanges();
    });

    it('disables Save and never sends a policy', () => {
      expect(component.canSave()).toBeFalse();
      expect(saveButton().disabled).toBeTrue();

      component.save(); // even if invoked directly
      expect(policyService.save).not.toHaveBeenCalled();
    });

    it('hides the editable form and shows the error instead', () => {
      const el = fixture.nativeElement as HTMLElement;
      expect(el.querySelector('#policy-allow-all')).toBeNull();
      expect(el.querySelector('li.rule-row')).toBeNull();
      expect(el.querySelector('.load-error')?.textContent).toContain('coordinator busy');
    });

    it('reports the failure in the status banner', () => {
      expect(TestBed.inject(StatusService).message()).toEqual({
        text: 'Failed to load the policy: coordinator busy',
        kind: 'err',
      });
    });

    it('re-enables editing after a successful retry', () => {
      policyService.get.and.returnValue(of(initialPolicy));
      component.refresh();
      fixture.detectChanges();
      expect(component.canSave()).toBeTrue();
      expect(component.ruleGroups.length).toBe(1);
    });
  });

  it('leaves the banner to authInterceptor on a 401/403', () => {
    const status = TestBed.inject(StatusService);
    status.show('token rejected — sign in again', 'err'); // what the interceptor shows
    policyService.get.and.returnValue(throwError(() => new HttpErrorResponse({ status: 401 })));
    component.refresh();
    expect(status.message()?.text).toBe('token rejected — sign in again');
    expect(component.canSave()).toBeFalse();
  });

  it('says the save succeeded when only the follow-up reload fails', () => {
    policyService.get.and.returnValue(
      throwError(() => new HttpErrorResponse({ status: 503, error: 'coordinator busy' })),
    );
    component.save();
    const msg = TestBed.inject(StatusService).message();
    expect(policyService.save).toHaveBeenCalled();
    expect(msg?.kind).toBe('err');
    expect(msg?.text).toContain('Policy saved, but reloading it failed: coordinator busy');
  });

  it('blocks Save until the first load completes', async () => {
    const pending = new Subject<Policy>();
    policyService.get.and.returnValue(pending);
    const slow = TestBed.createComponent(PolicyComponent).componentInstance;
    policyService.save.calls.reset();

    slow.save();
    expect(policyService.save).not.toHaveBeenCalled();

    pending.next(initialPolicy);
    pending.complete();
    expect(slow.canSave()).toBeTrue();
  });

  it('blocks a second Save while one is in flight', () => {
    const inFlight = new Subject<void>();
    policyService.save.and.returnValue(inFlight);
    component.save();
    component.save();
    expect(policyService.save).toHaveBeenCalledTimes(1);
  });
});
