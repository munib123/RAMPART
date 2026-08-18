# CrossVul Fix Pair: Improper Input Validation in typescript
**Pair ID:** 4194_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4194_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```typescript
Lines 1-40 of the vulnerable file.

/*
 * Wire
 * Copyright (C) 2018 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

import {app, BrowserWindow, ipcMain, session, shell} from 'electron';
import fileUrl = require('file-url');
import * as path from 'path';

import {EVENT_TYPE} from '../lib/eventType';
import * as locale from '../locale/locale';
import * as EnvironmentUtil from '../runtime/EnvironmentUtil';
import {config} from '../settings/config';
import {getLogger} from '../logging/getLogger';

const logger = getLogger(path.basename(__filename));

let webappVersion: string;

// Paths
const APP_PATH = path.join(app.getAppPath(), config.electronDirectory);
const iconFileName = `logo.${EnvironmentUtil.platform.IS_WINDOWS ? 'ico' : 'png'}`;
const iconPath = path.join(APP_PATH, 'img', iconFileName);

// Local files
const ABOUT_HTML = fileUrl(path.join(APP_PATH, 'html/about.html'));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,7 +17,7 @@
  *
  */
 
-import {app, BrowserWindow, ipcMain, session, shell} from 'electron';
+import {app, BrowserWindow, ipcMain, session} from 'electron';
 import fileUrl = require('file-url');
 import * as path from 'path';
 
@@ -26,6 +26,7 @@
 import * as EnvironmentUtil from '../runtime/EnvironmentUtil';
 import {config} from '../settings/config';
 import {getLogger} from '../logging/getLogger';
+import * as WindowUtil from '../window/WindowUtil';
 
 const logger = getLogger(path.basename(__filename));
 
@@ -89,14 +90,19 @@
       if (ABOUT_WINDOW_ALLOWLIST.includes(url)) {
         return callback({cancel: false});
       }
+    });
 
-      // Open HTTPS links in browser instead
-      if (url.startsWith('https://')) {
-        await shell.openExternal(url);
-      } else {
-        logger.info(`Attempt to open URL "${url}" in window prevented.`);
-        callback({redirectURL: ABOUT_HTML});
+    // Handle the new window event in the About Window
+    aboutWindow.webContents.on('new-window', (event, url) => {
+      event.preventDefault();
+
+      // Ensure the link does not come from a webview
+      if (typeof (event as any).sender.viewInstanceId !== 'undefined') {
+        logger.log('New window was created from a webview, aborting.');
+        return;
       }
+
+      return WindowUtil.openExternal(url, true);
     });
 
     // Locales
```
