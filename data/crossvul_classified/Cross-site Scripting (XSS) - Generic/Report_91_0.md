# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 91_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `91_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 1-21 of the vulnerable file.

{{ form_ajax('onUpdate', { model: user }) }}

    <div class="form-group">
        <label for="accountName">Full Name</label>
        <input name="name" type="text" class="form-control" id="accountName" value="{{ form_value('name') }}">
    </div>

    <div class="form-group">
        <label for="accountEmail">Email</label>
        <input name="email" type="email" class="form-control" id="accountEmail" value="{{ form_value('email') }}">
    </div>

    <div class="form-group">
        <label for="accountPassword">New Password</label>
        <input name="password" type="password" class="form-control" id="accountPassword">
    </div>

    <div class="form-group">
        <label for="accountPasswordConfirm">Confirm New Password</label>
        <input name="password_confirmation" type="password" class="form-control" id="accountPasswordConfirm">
    </div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,13 +1,13 @@
-{{ form_ajax('onUpdate', { model: user }) }}
+{{ form_ajax('onUpdate') }}
 
     <div class="form-group">
         <label for="accountName">Full Name</label>
-        <input name="name" type="text" class="form-control" id="accountName" value="{{ form_value('name') }}">
+        <input name="name" type="text" class="form-control" id="accountName" value="{{ user.name }}">
     </div>
 
     <div class="form-group">
         <label for="accountEmail">Email</label>
-        <input name="email" type="email" class="form-control" id="accountEmail" value="{{ form_value('email') }}">
+        <input name="email" type="email" class="form-control" id="accountEmail" value="{{ user.email }}">
     </div>
 
     <div class="form-group">
```
