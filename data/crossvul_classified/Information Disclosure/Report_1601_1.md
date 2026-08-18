# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in javascript
**Pair ID:** 1601_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1601_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```javascript
Lines 1-21 of the vulnerable file.

// Publish the current user

Meteor.publish('currentUser', function() {
  var user = Meteor.users.find({_id: this.userId});
  return user;
});

// publish all users for admins to make autocomplete work
// TODO: find a better way

Meteor.publish('allUsersAdmin', function() {
  var selector = getSetting('requirePostInvite') ? {isInvited: true} : {}; // only users that can post
  if (isAdminById(this.userId)) {
    return Meteor.users.find(selector, {fields: {
      _id: true,
      profile: true,
      slug: true
    }});
  }
  return [];
});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 // Publish the current user
 
 Meteor.publish('currentUser', function() {
-  var user = Meteor.users.find({_id: this.userId});
+  var user = Meteor.users.find({_id: this.userId}, {fields: ownUserOptions});
   return user;
 });
 
```
