import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of } from 'rxjs';

import { PolicyComponent } from './policy.component';
import { PolicyService } from '../core/policy.service';
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
});
