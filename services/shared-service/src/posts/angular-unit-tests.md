# Writing Unit Tests for Angular 12 Forms using Jasmine by configuring a Testing Module (like a Pro )

<!-- add image -->
![Angular Unit Tests](https://media.licdn.com/dms/image/C5612AQGdSRtoQO3cVA/article-cover_image-shrink_720_1280/0/1620601880759?e=2147483647&v=beta&t=WseLYznA4h-XcB7QzOBRdX0fUW1RKqObFzvtxZnB7o0)

Unit Testing is important for any project just to ensure that working code is shipped to production. In this case, we are going to look at how we can test Angular 12 forms. Let us dive into it.

Let us start with a very simple project that has a component that renders a basic form.

#### myform.component.html
```html
<div fxlayout="row">

  <div fxflex="" fxlayoutalign="center">

    <form form="" formgroup="">

      <input formcontrolname="username" id="" type="text" />

    </form>

  </div>

</div>
```

#### myform.component.ts
```typescript
import {Component, OnInit} from '@angular/core';

import {FormBuilder, FormGroup, Validators} from '@angular/forms';



@Component({

  selector: 'app-my-form',

  templateUrl: './my-form.component.html',

  styleUrls: ['./my-form.component.sass'],

})

export class MyFormComponent implements OnInit {

  form: FormGroup = {} as FormGroup;



  constructor(private fb: FormBuilder) {}



  ngOnInit(): void {

    this.form = this.fb.group({

      username: [

        '',

        [

          Validators.required,

          Validators.minLength(3),

          Validators.maxLength(10),

        ],

      ],

    });

  }

}
```

#### myform.component.spec.ts
```typescript
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { MyFormComponent } from './my-form.component';

describe('MyFormComponent', () => {
  let component: MyFormComponent;
  let fixture: ComponentFixture<MyFormComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ MyFormComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(MyFormComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
```
To get the code for the whole project, this is the link to the [Github Repository](https://github.com/elonaire/ng-tests).

## Running your first test
To run the tests together with the code coverage report, we type ```ng test --code-coverage``` in the terminal, but we are presented with the following error in the terminal:

```bash
NullInjectorError: No provider for FormBuilder!
```
The coverage report is as follows:
    
```bash
=============================== Coverage summary ===============================
Statements   : 72.73% ( 8/11 )
Branches     : 100% ( 0/0 )
Functions    : 0% ( 0/2 )
Lines        : 66.67% ( 6/9 )
================================================================================
```

## Understanding the principle behind the Component TestBed and how to configure it
This error means that we have failed to inject the missing providers into the Testing module as well, just like we injected in the component and imported it into the ```app.module.ts``` file.

Now, this calls for understanding how testing works in angular, let us have a look at the spec file in depth. From the project, ```MyFormComponent``` is declared in ```AppModule```. The testbed has to be isolated and it has to mimic the module in which the component is declared. So, we have to configure the testbed in such a manner that, the component is declared in the testing module, together with any services or providers that were injected into the component. The correct configuration will appear as follows:

```typescript
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { MyFormComponent } from './my-form.component';

import { FormBuilder } from '@angular/forms';

describe('MyFormComponent', () => {
  let component: MyFormComponent;
  let fixture: ComponentFixture<MyFormComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ MyFormComponent ],
      providers: [ FormBuilder ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(MyFormComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
```
If we now run ```ng test --code-coverage``` once again, or assuming it automatically refreshes after applying the above changes, you get the following output in your terminal: 

```bash
TOTAL: 3 SUCCESS
=============================== Coverage summary ==============================
Statements   : 100% ( 11/11 )
Branches     : 100% ( 0/0 )
Functions    : 100% ( 2/2 )
Lines        : 100% ( 9/9 )
===============================================================================
```

Hurray! You did it!! Right?

![Hurray](https://media.giphy.com/media/hnl83xVQxpqJG/giphy.gif)

Well..., just for now, let us add more fields and functions to our form and see what happens.

#### myform.component.ts
```typescript
import {Component, OnInit} from '@angular/core';
import {FormBuilder, FormGroup, Validators} from '@angular/forms';

@Component({
  selector: 'app-my-form',
  templateUrl: './my-form.component.html',
  styleUrls: ['./my-form.component.sass'],
})
export class MyFormComponent implements OnInit {
  form: FormGroup = {} as FormGroup;

  constructor(private fb: FormBuilder) {}

  ngOnInit(): void {
    this.form = this.fb.group({
      username: [
        '',
        [
          Validators.required,
          Validators.minLength(3),
          Validators.maxLength(10),
        ],
      ],
      password: [
        '',
        [
          Validators.required,
          Validators.minLength(3),
          Validators.maxLength(10),
          Validators.pattern('[a-zA-Z0-9]{3,10}'),
        ],
      ],
    });
  }

  login() {
    alert('Logged in as: ' + this.form.value.username);
  }
}
```

#### myform.component.html
```html
<div fxLayout="row">
  <div fxFlex="" fxLayoutAlign="center">
    <form [formGroup]="form">
      <input type="text" placeholder="username" formControlName="username" 
      id="username">
      <input type="password" placeholder="password" formControlName="password" 
     id="password">
      <button [disabled]="form?.invalid" (click)="login()" id="login-button">
      Login
      </button>
    </form>
  </div>
</div>
```

With the above updates, you will note that the test coverage will drop:
```bash
TOTAL: 3 SUCCESS

=============================== Coverage summary ==============================
Statements   : 91.67% ( 11/12 )
Branches     : 100% ( 0/0 )
Functions    : 66.67% ( 2/3 )
Lines        : 90% ( 9/10 )
===============================================================================
```

Now let us write a test case to cover the login function, we'll have to simulate exactly what a human user would do. Which is, fill the form to suit the validations then click the "Login" button. Let us now write the test cases.

#### myform.component.spec.ts
```typescript
import {ComponentFixture, TestBed} from '@angular/core/testing';
import {FormBuilder, FormsModule, ReactiveFormsModule} from '@angular/forms';

import {MyFormComponent} from './my-form.component';

describe('MyFormComponent', () => {
  let component: MyFormComponent;
  let fixture: ComponentFixture<MyFormComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [MyFormComponent],
      providers: [{provide: FormBuilder, useClass: FormBuilder}],
      imports: [FormsModule, ReactiveFormsModule]
    }).compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(MyFormComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  // should render the form
  it('should render the form', () => {
    const compiled = fixture.debugElement.nativeElement;
    const userNameInput = compiled.querySelector('#username');
    const passwordInput = compiled.querySelector('#password');
    const loginButton = compiled.querySelector('#login-button');

    expect(userNameInput).toBeTruthy();
    expect(passwordInput).toBeTruthy();
    expect(loginButton).toBeTruthy();
  });

  // should fill the form to be valid
  it('should fill the form to be valid', () => {
    const form = component.form;
    const nameInput = form.controls.username;
    const passwordInput = form.controls.password;
    expect(form.valid).toBeFalsy();

    // set form field values to be valid
    nameInput.setValue('tenka'); // min 3 chars
    passwordInput.setValue('tenka95'); // min 3 chars max 10 chars

    expect(form.valid).toBeTruthy();
  });

  // should submit the form
  it('should submit the form', () => {
    const compiled = fixture.debugElement.nativeElement;
    const form = component.form;
    const loginButton = compiled.querySelector('#login-button');
    const nameInput = form.controls.username;
    const passwordInput = form.controls.password;

    nameInput.setValue('tenka');
    passwordInput.setValue('tenka95');
    fixture.detectChanges(); // trigger change detection

    // spy on the login method through the button's click event
    spyOn(component, 'login').and.callThrough();
    loginButton.click();

    expect(component.login).toHaveBeenCalled();
  });
});
```

Now, if you run the tests again, you will get the following output:

```bash
TOTAL: 6 SUCCESS

=============================== Coverage summary ==============================
Statements   : 100% ( 12/12 )
Branches     : 100% ( 0/0 )
Functions    : 100% ( 3/3 )
Lines        : 100% ( 10/10 )
===============================================================================
```

Congratulations on completing this chapter with me, I plan that the next article on Unit Testing in Angular will be about using the component harness. Kindly leave a comment, goodbye, for now, see you on the next one.
