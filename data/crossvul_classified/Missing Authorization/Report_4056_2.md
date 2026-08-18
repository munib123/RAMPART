# CrossVul Fix Pair: Missing Authorization in coffeescript
**Pair ID:** 4056_2
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** coffeescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4056_2`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```coffeescript
Lines 60-100 of the vulnerable file.

    new App.TicketStats(
      el:   elLocal.find('.js-ticket-stats')
      user: user
    )

    @html elLocal

    new App.UpdateTastbar(
      genericObject: user
    )

  setPosition: (position) =>
    @$('.profile').scrollTop(position)

  currentPosition: =>
    @$('.profile').scrollTop()

class ActionRow extends App.ObserverActionRow
  model: 'User'
  observe:
    organization_id: true

  showHistory: (user) =>
    new App.UserHistory(
      user_id: user.id
      container: @el.closest('.content')
    )

  editUser: (user) =>
    new App.ControllerGenericEdit(
      id: user.id
      genericObject: 'User'
      screen: 'edit'
      pageData:
        title: 'Users'
        object: 'User'
        objects: 'Users'
      container: @el.closest('.content')
    )

  newTicket: (user) =>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -77,6 +77,8 @@
 class ActionRow extends App.ObserverActionRow
   model: 'User'
   observe:
+    verified: true
+    source: true
     organization_id: true
 
   showHistory: (user) =>
@@ -99,6 +101,25 @@
 
   newTicket: (user) =>
     @navigate("ticket/create/customer/#{user.id}")
+
+  resendVerificationEmail: (user) =>
+    @ajax(
+      id:          'email_verify_send'
+      type:        'POST'
+      url:         @apiPath + '/users/email_verify_send'
+      data:        JSON.stringify(email: user.email)
+      processData: true
+      success: (data, status, xhr) =>
+        @notify
+          type:      'success'
+          msg:       App.i18n.translateContent('Email sent to "%s". Please let the user verify his email address.', user.email)
+          removeAll: true
+      error: (data, status, xhr) =>
+        @notify
+          type:      'error'
+          msg:       App.i18n.translateContent('Failed to sent Email "%s". Please contact an administrator.', user.email)
+          removeAll: true
+    )
 
   actions: (user) =>
     actions = [
@@ -120,6 +141,13 @@
         title:    'Edit'
         callback: @editUser
       }
+
+      if user.verified isnt true && user.source is 'signup'
+        actions.push({
+          name:     'resend_verification_email'
+          title:    'Resend verification email'
+          callback: @resendVerificationEmail
+        })
 
     actions
 
```
