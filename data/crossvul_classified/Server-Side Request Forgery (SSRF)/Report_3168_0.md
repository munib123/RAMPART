# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in javascript
**Pair ID:** 3168_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3168_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```javascript
Lines 133-173 of the vulnerable file.

  this.route("newAdminUsers", {
    path: "/admin/users",
    controller: newAdminRoute,
  });
  this.route("newAdminUserInvite", {
    path: "/admin/users/invite",
    controller: newAdminRoute,
  });
  this.route("newAdminUserDetails", {
    path: "/admin/users/:userId",
    controller: newAdminRoute,
  });
  this.route("newAdminAppSources", {
    path: "/admin/app-sources",
    controller: newAdminRoute,
  });
  this.route("newAdminPreinstalledApps", {
    path: "/admin/preinstalled-apps",
    controller: newAdminRoute,
  });
  this.route("newAdminMaintenance", {
    path: "/admin/maintenance",
    controller: newAdminRoute,
  });
  this.route("newAdminStatus", {
    path: "/admin/status",
    controller: newAdminRoute,
  });
  this.route("newAdminPersonalization", {
    path: "/admin/personalization",
    controller: newAdminRoute,
  });
  this.route("newAdminNetworkCapabilities", {
    path: "/admin/network-capabilities",
    controller: newAdminRoute,
  });
  this.route("newAdminStats", {
    path: "/admin/stats",
    controller: newAdminRoute,
  });
  this.route("newAdminOrganization", {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -150,6 +150,10 @@
     path: "/admin/preinstalled-apps",
     controller: newAdminRoute,
   });
+  this.route("newAdminNetworking", {
+    path: "/admin/networking",
+    controller: newAdminRoute,
+  });
   this.route("newAdminMaintenance", {
     path: "/admin/maintenance",
     controller: newAdminRoute,
```
