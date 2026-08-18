# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 591_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `591_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 96-136 of the vulnerable file.

      params.noDebugger == null || params.noDebugger !== 'true';

    track('nuclide-attach-hhvm-deeplink', {
      pathString,
      line,
      addBreakpoint,
      source,
    });

    if (this._remoteProjectsService == null) {
      atom.notifications.addError('The remote project service is unavailable.');
      return;
    } else {
      const remoteProjectsService = this._remoteProjectsService;
      await new Promise(resolve =>
        remoteProjectsService.waitForRemoteProjectReload(resolve),
      );
    }

    const host = nuclideUri.getHostname(pathString);
    const cwd = nuclideUri.createRemoteUri(host, hackRootString);
    const notification = atom.notifications.addInfo(
      startDebugger
        ? `Connecting to ${host} and attaching debugger...`
        : `Connecting to ${host}...`,
      {
        dismissable: true,
      },
    );

    invariant(this._remoteProjectsService != null);
    const remoteConnection = await this._remoteProjectsService.createRemoteConnection(
      {
        host,
        cwd: nuclideUri.getPath(cwd),
        displayTitle: host,
      },
    );

    if (remoteConnection == null) {
      atom.notifications.addError(`Could not connect to ${host}`);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -113,6 +113,17 @@
     }
 
     const host = nuclideUri.getHostname(pathString);
+
+    // Allow only valid hostname characters, per RFC 952:
+    // https://tools.ietf.org/html/rfc952
+    const invalidMatch = host.match(/[^A-Za-z0-9\-._]+/);
+    if (invalidMatch != null) {
+      atom.notifications.addError(
+        'The specified host name contained invalid characters.',
+      );
+      return;
+    }
+
     const cwd = nuclideUri.createRemoteUri(host, hackRootString);
     const notification = atom.notifications.addInfo(
       startDebugger
```
