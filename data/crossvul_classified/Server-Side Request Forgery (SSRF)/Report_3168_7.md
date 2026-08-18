# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in javascript
**Pair ID:** 3168_7
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3168_7`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```javascript
Lines 1-32 of the vulnerable file.

// Minimal tooling for doing run-at-least-once, ordered migrations.
//
// Because migrations can experience partial failure and likely have
// side-effects, we should be careful to make sure all migrations are
// idempotent and safe to accidentally run multiple times.

import { Meteor } from "meteor/meteor";
import { _ } from "meteor/underscore";
import { Match } from "meteor/check";
import { userPictureUrl, fetchPicture } from "/imports/server/accounts/picture.js";
import { waitPromise } from "/imports/server/async-helpers.js";

const Future = Npm.require("fibers/future");
const Url = Npm.require("url");
const Crypto = Npm.require("crypto");

const updateLoginStyleToRedirect = function (db, backend) {
  const configurations = Package["service-configuration"].ServiceConfiguration.configurations;
  ["google", "github"].forEach(function (serviceName) {
    const config = configurations.findOne({ service: serviceName });
    if (config && config.loginStyle !== "redirect") {
      configurations.update({ service: serviceName }, { $set: { loginStyle: "redirect" } });
    }
  });
};

const enableLegacyOAuthProvidersIfNotInSettings = function (db, backend) {
  // In the before time, Google and Github login were enabled by default.
  //
  // This actually didn't make much sense, required the first user to configure
  // OAuth, and had some trust-the-first-user properties that weren't totally
  // secure.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,7 @@
 import { Match } from "meteor/check";
 import { userPictureUrl, fetchPicture } from "/imports/server/accounts/picture.js";
 import { waitPromise } from "/imports/server/async-helpers.js";
+import { PRIVATE_IPV4_ADDRESSES, PRIVATE_IPV6_ADDRESSES } from "/imports/constants.js";
 
 const Future = Npm.require("fibers/future");
 const Url = Npm.require("url");
@@ -775,6 +776,15 @@
 
   db.notifications.remove({ "admin.type": "cantRenewFeatureKey" });
   db.notifications.remove({ "admin.type": "trialFeatureKeyExpired" });
+}
+
+function setIpBlacklist(db, backend) {
+  if (Meteor.settings.public.isTesting) {
+    db.collections.settings.insert({ _id: "ipBlacklist", value: "192.168.0.0/16" });
+  } else {
+    const defaultIpBlacklist = PRIVATE_IPV4_ADDRESSES.concat(PRIVATE_IPV6_ADDRESSES).join("\n");
+    db.collections.settings.insert({ _id: "ipBlacklist", value: defaultIpBlacklist });
+  }
 }
 
 // This must come after all the functions named within are defined.
@@ -813,6 +823,7 @@
   setNewServer,
   addMembraneRequirementsToIdentities,
   addEncryptionToFrontendRefIpNetwork,
+  setIpBlacklist,
 ];
 
 const NEW_SERVER_STARTUP = [
```
