# CrossVul Fix Pair: Insufficient Verification of Data Authenticity in javascript
**Pair ID:** 4289_2
**Vulnerability Class:** Insufficient Verification of Data Authenticity
**CWE:** CWE-345
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4289_2`)

## Vulnerability Information & PoC

## Description
Insufficient Verification of Data Authenticity - The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Vulnerable Code
```javascript
Lines 1-28 of the vulnerable file.

/* global __dirname, process */

const {
    BrowserWindow,
    Menu,
    app,
    ipcMain,
    shell
} = require('electron');
const contextMenu = require('electron-context-menu');
const debug = require('electron-debug');
const isDev = require('electron-is-dev');
const { autoUpdater } = require('electron-updater');
const windowStateKeeper = require('electron-window-state');
const {
    initPopupsConfigurationMain,
    getPopupTarget,
    setupAlwaysOnTopMain,
    setupPowerMonitorMain,
    setupScreenSharingMain
} = require('jitsi-meet-electron-utils');
const path = require('path');
const URL = require('url');
const config = require('./app/features/config');

const showDevTools = Boolean(process.env.SHOW_DEV_TOOLS) || (process.argv.indexOf('--show-dev-tools') > -1);

// We need this because of https://github.com/electron/electron/issues/18214
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,8 +4,7 @@
     BrowserWindow,
     Menu,
     app,
-    ipcMain,
-    shell
+    ipcMain
 } = require('electron');
 const contextMenu = require('electron-context-menu');
 const debug = require('electron-debug');
@@ -22,6 +21,7 @@
 const path = require('path');
 const URL = require('url');
 const config = require('./app/features/config');
+const { openExternalLink } = require('./app/features/utils/openExternalLink');
 
 const showDevTools = Boolean(process.env.SHOW_DEV_TOOLS) || (process.argv.indexOf('--show-dev-tools') > -1);
 
@@ -211,7 +211,7 @@
 
         if (!target || target === 'browser') {
             event.preventDefault();
-            shell.openExternal(url);
+            openExternalLink(url);
         }
     });
     mainWindow.on('closed', () => {
```
