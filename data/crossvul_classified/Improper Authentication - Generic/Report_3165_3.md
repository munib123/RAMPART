# CrossVul Fix Pair: Improper Authentication in javascript
**Pair ID:** 3165_3
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3165_3`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```javascript
Lines 168-208 of the vulnerable file.

      isAdmin: Boolean,
    });

    const userId = userInfo.userId;
    if (userId === Meteor.userId() && !userInfo.isAdmin) {
      throw new Meteor.Error(403, "User cannot remove admin permissions from itself.");
    }

    Meteor.users.update({ _id: userId }, { $set: _.omit(userInfo, ["_id", "userId"]) });
  },

  testSend: function (token, smtpConfig, to) {
    checkAuth(token);
    check(smtpConfig, smtpConfigShape);
    check(to, String);
    const { returnAddress, ...restConfig } = smtpConfig;

    try {
      sendEmail({
        to: to,
        from: globalDb.getServerTitle() + " <" + returnAddress + ">",
        subject: "Testing your Sandstorm's SMTP setting",
        text: "Success! Your outgoing SMTP is working.",
        smtpConfig: restConfig,
      });
    } catch (e) {
      // Attempt to give more accurate error messages for a variety of known failure modes,
      // and the actual exception data in the event a user hits a new failure mode.
      if (e.syscall === "getaddrinfo") {
        if (e.code === "EIO" || e.code === "ENOTFOUND") {
          throw new Meteor.Error("getaddrinfo " + e.code, "Couldn't resolve \"" + smtpConfig.hostname + "\" - check for typos or broken DNS.");
        }
      } else if (e.syscall === "connect") {
        if (e.code === "ECONNREFUSED") {
          throw new Meteor.Error("connect ECONNREFUSED", "Server at " + smtpConfig.hostname + ":" + smtpConfig.port + " refused connection.  Check your settings, firewall rules, and that your mail server is up.");
        }
      } else if (e.name === "AuthError") {
        throw new Meteor.Error("auth error", "Authentication failed.  Check your credentials.  Message from " +
                smtpConfig.hostname + ": " + e.data);
      }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -185,7 +185,7 @@
     try {
       sendEmail({
         to: to,
-        from: globalDb.getServerTitle() + " <" + returnAddress + ">",
+        from: { name: globalDb.getServerTitle(), address: returnAddress },
         subject: "Testing your Sandstorm's SMTP setting",
         text: "Success! Your outgoing SMTP is working.",
         smtpConfig: restConfig,
@@ -224,10 +224,11 @@
 
   sendInvites: function (token, origin, from, list, subject, message, quota) {
     checkAuth(token);
-    check([origin, from, list, subject, message], [String]);
+    check(from, { name: String, address: String });
+    check([origin, list, subject, message], [String]);
     check(quota, Match.OneOf(undefined, null, Number));
 
-    if (!from.trim()) {
+    if (!from.address.trim()) {
       throw new Meteor.Error(403, "Must enter 'from' address.");
     }
 
```
