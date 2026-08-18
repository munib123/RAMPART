# CrossVul Fix Pair: Missing Authorization in coffeescript
**Pair ID:** 4056_0
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** coffeescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4056_0`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```coffeescript
Lines 1-24 of the vulnerable file.

class Index extends App.Controller
  constructor: ->
    super
    @authenticateCheckRedirect()
    @verifyCall()

  verifyCall: =>
    @ajax(
      id:          'email_verify'
      type:        'POST'
      url:         "#{@apiPath}/users/email_verify"
      data:        JSON.stringify(token: @token)
      processData: true
      success:     @success
      error:       @error
    )

  success: =>
    new Success(el: @el)

  error: =>
    new Fail(el: @el)

class Success extends App.ControllerContent
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,6 @@
 class Index extends App.Controller
   constructor: ->
     super
-    @authenticateCheckRedirect()
     @verifyCall()
 
   verifyCall: =>
@@ -11,45 +10,23 @@
       url:         "#{@apiPath}/users/email_verify"
       data:        JSON.stringify(token: @token)
       processData: true
-      success:     @success
-      error:       @error
-    )
+      success: (data, status, xhr) =>
+        App.Auth.loginCheck()
+        @navigate '#'
 
-  success: =>
-    new Success(el: @el)
+        @notify
+          type:      'success'
+          msg:       App.i18n.translateContent('Woo hoo! Your email address has been verified!')
+          removeAll: true
+          timeout: 2000
 
-  error: =>
-    new Fail(el: @el)
+      error: (data, status, xhr) =>
+        @navigate '#'
 
-class Success extends App.ControllerContent
-  constructor: ->
-    super
-    @render()
-
-    # rerender view, e. g. on language change
-    @bind 'ui:rerender', =>
-      @render()
-
-  render: =>
-    @renderScreenSuccess(
-      detail: 'Woo hoo! Your email address has been verified!'
-    )
-    delay = =>
-      @navigate '#'
-    @delay(delay, 20500)
-
-class Fail extends App.ControllerContent
-  constructor: ->
-    super
-    @render()
-
-    # rerender view, e. g. on language change
-    @bind 'ui:rerender', =>
-      @render()
-
-  render: =>
-    @renderScreenError(
-      detail: 'Unable to verify email. Please contact your administrator.'
+        @notify
+          type:      'error'
+          msg:       App.i18n.translateContent('Unable to verify email. Please contact your administrator.')
+          removeAll: true
     )
 
 App.Config.set('email_verify/:token', Index, 'Routes')
```
