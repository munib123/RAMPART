# CrossVul Fix Pair: Improper Authentication in javascript
**Pair ID:** 3165_2
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3165_2`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```javascript
Lines 182-222 of the vulnerable file.

  let subject;
  let text;

  const rootHostname = Url.parse(options.rootUrl).hostname;

  if (!options.linking) {
    subject = "Log in to " + rootHostname;
    text = "To confirm this email address on ";
  } else {
    subject = "Confirm this email address on " + rootHostname;
    text = "To confirm this email address on ";
  }

  text = text + rootHostname + ", click on the following link:\n\n" +
      makeTokenUrl(email, token, options) + "\n\n" +
      "Alternatively, enter the following one-time authentication code into the log-in form:\n\n" +
      token;

  const sendOptions = {
    to:  email,
    from: db.getServerTitle() + " <" + db.getReturnAddress() + ">",
    subject: subject,
    text: text,
  };

  sendEmail(sendOptions);
};

const parsedRootUrl = Url.parse(process.env.ROOT_URL);
///
/// CREATING USERS
///
// returns the user id
const createAndEmailTokenForUser = function (db, email, options) {
  check(email, String);
  check(options, {
    resumePath: String,
    linking: Match.Optional({ allowLogin: Boolean }),
    rootUrl: String,
  });

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -199,7 +199,7 @@
 
   const sendOptions = {
     to:  email,
-    from: db.getServerTitle() + " <" + db.getReturnAddress() + ">",
+    from: { name: globalDb.getServerTitle(), address: db.getReturnAddress() },
     subject: subject,
     text: text,
   };
```
