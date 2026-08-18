# CrossVul Fix Pair: Insufficient Verification of Data Authenticity in javascript
**Pair ID:** 4289_1
**Vulnerability Class:** Insufficient Verification of Data Authenticity
**CWE:** CWE-345
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4289_1`)

## Vulnerability Information & PoC

## Description
Insufficient Verification of Data Authenticity - The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Vulnerable Code
```javascript
Lines 1-22 of the vulnerable file.

const createElectronStorage = require('redux-persist-electron-storage');
const { ipcRenderer, shell, remote } = require('electron');
const os = require('os');
const url = require('url');

const jitsiMeetElectronUtils = require('jitsi-meet-electron-utils');

const protocolRegex = /^https?:/i;

/**
 * Opens the given link in an external browser.
 *
 * @param {string} link - The link (URL) that should be opened in the external browser.
 * @returns {void}
 */
function openExternalLink(link) {
    let u;

    try {
        u = url.parse(link);
    } catch (e) {
        return;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,31 +1,9 @@
 const createElectronStorage = require('redux-persist-electron-storage');
-const { ipcRenderer, shell, remote } = require('electron');
+const { ipcRenderer, remote } = require('electron');
 const os = require('os');
-const url = require('url');
+const jitsiMeetElectronUtils = require('jitsi-meet-electron-utils');
+const { openExternalLink } = require('../features/utils/openExternalLink');
 
-const jitsiMeetElectronUtils = require('jitsi-meet-electron-utils');
-
-const protocolRegex = /^https?:/i;
-
-/**
- * Opens the given link in an external browser.
- *
- * @param {string} link - The link (URL) that should be opened in the external browser.
- * @returns {void}
- */
-function openExternalLink(link) {
-    let u;
-
-    try {
-        u = url.parse(link);
-    } catch (e) {
-        return;
-    }
-
-    if (protocolRegex.test(u.protocol)) {
-        shell.openExternal(link);
-    }
-}
 
 const whitelistedIpcChannels = [ 'protocol-data-msg', 'renderer-ready' ];
 
@@ -34,7 +12,6 @@
     osUserInfo: os.userInfo,
     openExternalLink,
     jitsiMeetElectronUtils,
-    shellOpenExternal: shell.openExternal,
     getLocale: remote.app.getLocale,
     ipc: {
         on: (channel, listener) => {
```
