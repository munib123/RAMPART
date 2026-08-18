# CrossVul Fix Pair: Improper Authentication in javascript
**Pair ID:** 3165_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3165_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```javascript
Lines 58-98 of the vulnerable file.

      configured = false;
    },
  });
});

const getPool = function (smtpConfig) {
  if (smtpConfig) {
    return makePool(smtpConfig);
  } else if (!configured) {
    configured = true;
    const config = getSmtpConfig();
    if (config) {
      pool = makePool(config);
    }
  }

  return pool;
};

const smtpSend = function (pool, mailOptions) {
  pool._futureWrappedSendMail(mailOptions).wait();
};

const rawSend = function (mailOptions, smtpConfig) {
  // Sends an email mailOptions object structured as described in
  // https://github.com/nodemailer/mailcomposer#e-mail-message-fields
  // across the transport described by smtpConfig.
  const pool = getPool(smtpConfig);
  if (pool) {
    smtpSend(pool, mailOptions);
  } else {
    throw new Error("SMTP pool is misconfigured.");
  }
};

// Old comment below
/**
 * Send an email.
 *
 * Connects to the mail server configured via the MAIL_URL environment
 * variable. If unset, prints formatted message to stdout. The "from" option
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,13 +75,49 @@
 };
 
 const smtpSend = function (pool, mailOptions) {
+  console.log(mailOptions);
   pool._futureWrappedSendMail(mailOptions).wait();
 };
+
+// From http://emailregex.com/, which claims this is the W3C standard for the HTML input element,
+// although their link is broken and I can find no evidence that this is a standard. The page
+// lists several regexes, ostensibly in syntaxes intended for different programming languages,
+// but each regex is in fact substantially different for no apparent reason.
+//
+// The most important thing here is that we disallow separators that might allow a user to confuse
+// nodemailer into thinking the address is a list. Unfortunately, nodemailer will happily separate
+// strings into lists splitting on all kinds of separator characters, such as commas, semicolons,
+// etc. This regex should accomplish that both by disallowing the separators, and by disallowing
+// multiple @ signs. The rest is for show.
+const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/;
+
+function validateEmail(email) {
+  if (email instanceof Array) {
+    email.forEach(validateEmail);
+  } else if (typeof email === "object" && "address" in email) {
+    validateEmail(email.address);
+  } else if (email) {
+    check(email, String);
+
+    if (!email.match(EMAIL_REGEX)) {
+      console.log(email);
+      throw new Meteor.Error(400, "invalid e-mail address");
+    }
+  }
+}
 
 const rawSend = function (mailOptions, smtpConfig) {
   // Sends an email mailOptions object structured as described in
   // https://github.com/nodemailer/mailcomposer#e-mail-message-fields
   // across the transport described by smtpConfig.
+
+  // For fields that are supposed to be lists of addresses, if only a single string is provided,
+  // wrap it in an array. This prevents nodemailer from interpreting the address as a
+  // comma-separated list.
+  ["from", "to", "cc", "bcc", "replyTo"].forEach(field => {
+    validateEmail(mailOptions[field]);
+  });
+
   const pool = getPool(smtpConfig);
   if (pool) {
     smtpSend(pool, mailOptions);
```
