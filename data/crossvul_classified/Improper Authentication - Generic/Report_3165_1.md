# CrossVul Fix Pair: Improper Authentication in javascript
**Pair ID:** 3165_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3165_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```javascript
Lines 1499-1539 of the vulnerable file.

    return setting ? setting.value : "";  // empty if subscription is not ready.
  },

  getSmtpConfig() {
    const setting = this.collections.settings.findOne({ _id: "smtpConfig" });
    return setting ? setting.value : undefined; // undefined if subscription is not ready.
  },

  getReturnAddress() {
    const config = this.getSmtpConfig();
    return config && config.returnAddress || ""; // empty if subscription is not ready.
  },

  getReturnAddressWithDisplayName(identityId) {
    check(identityId, String);
    const identity = this.getIdentity(identityId);
    const displayName = identity.profile.name + " (via " + this.getServerTitle() + ")";

    // First remove any instances of characters that cause trouble for SimpleSmtp. Ideally,
    // we could escape such characters with a backslash, but that does not seem to help here.
    const sanitized = displayName.replace(/"|<|>|\\|\r/g, "");

    return "\"" + sanitized + "\" <" + this.getReturnAddress() + ">";
  },

  getPrimaryEmail(accountId, identityId) {
    check(accountId, String);
    check(identityId, String);

    const identity = this.getIdentity(identityId);
    const senderEmails = SandstormDb.getVerifiedEmails(identity);
    const senderPrimaryEmail = _.findWhere(senderEmails, { primary: true });
    const accountPrimaryEmailAddress = this.getUser(accountId).primaryEmail;
    if (_.findWhere(senderEmails, { email: accountPrimaryEmailAddress })) {
      return accountPrimaryEmailAddress;
    } else if (senderPrimaryEmail) {
      return senderPrimaryEmail.email;
    } else {
      return null;
    }
  },
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1516,9 +1516,11 @@
 
     // First remove any instances of characters that cause trouble for SimpleSmtp. Ideally,
     // we could escape such characters with a backslash, but that does not seem to help here.
+    // TODO(cleanup): Unclear whether this sanitization is still necessary now that we return a
+    //   structured object and have moved to nodemailer. I'm not touching it for now.
     const sanitized = displayName.replace(/"|<|>|\\|\r/g, "");
 
-    return "\"" + sanitized + "\" <" + this.getReturnAddress() + ">";
+    return { name: sanitized, address: this.getReturnAddress() };
   },
 
   getPrimaryEmail(accountId, identityId) {
```
