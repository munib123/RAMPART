# CrossVul Fix Pair: Missing Authorization in coffeescript
**Pair ID:** 4056_1
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** coffeescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4056_1`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```coffeescript
Lines 1-25 of the vulnerable file.

class Index extends App.ControllerContent
  events:
    'submit form': 'submit'
    'click .submit': 'submit'
    'click .cancel': 'cancel'

  constructor: ->
    super

    # go back if feature is not enabled
    if !@Config.get('user_create_account')
      @navigate '#'
      return

    @navHide()

    # set title
    @title 'Sign up'
    @navupdate '#signup'

    @render()

  render: ->

    @html App.view('signup')()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,6 +2,7 @@
   events:
     'submit form': 'submit'
     'click .submit': 'submit'
+    'click .js-submitResend': 'resend'
     'click .cancel': 'cancel'
 
   constructor: ->
@@ -61,31 +62,41 @@
     # save user
     user.save(
       done: (r) =>
-        App.Auth.login(
-          data:
-            username: @params.login
-            password: @params.password
-          success: @success
-          error: @error
+        @html App.view('signup/verify')(
+          email: @params.email
         )
       fail: (settings, details) =>
         @formEnable(e)
-        @form.showAlert(details.error_human || details.error || 'Unable to update object!')
+        if _.isArray(details.error)
+          @form.showAlert( App.i18n.translateInline( details.error[0], details.error[1] ) )
+        else
+          @form.showAlert(details.error_human || details.error || 'Unable to update object!')
     )
 
-  success: (data, status, xhr) =>
+  resend: (e) =>
+    e.preventDefault()
+    @formDisable(e)
+    @resendParams = @formParam(e.target)
 
-    # login check
-    App.Auth.loginCheck()
+    @ajax(
+      id:          'email_verify_send'
+      type:        'POST'
+      url:         @apiPath + '/users/email_verify_send'
+      data:        JSON.stringify(email: @resendParams.email)
+      processData: true
+      success: (data, status, xhr) =>
+        @formEnable(e)
 
-    # add notify
-    @notify
-      type:      'success'
-      msg:       App.i18n.translateContent('Thanks for joining. Email sent to "%s". Please verify your email address.', @params.email)
-      removeAll: true
+        # add notify
+        @notify
+          type:      'success'
+          msg:       App.i18n.translateContent('Email sent to "%s". Please verify your email address.', @params.email)
+          removeAll: true
 
-    # redirect to #
-    @navigate '#'
+        if data.token && @Config.get('developer_mode') is true
+          @navigate "#email_verify/#{data.token}"
+      error: @error
+    )
 
   error: (xhr, statusText, error) =>
     detailsRaw = xhr.responseText
```
