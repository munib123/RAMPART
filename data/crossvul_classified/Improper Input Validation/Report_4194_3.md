# CrossVul Fix Pair: Improper Input Validation in typescript
**Pair ID:** 4194_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4194_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```typescript
Lines 1-41 of the vulnerable file.

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

import autoLaunch = require('auto-launch');
import {dialog, globalShortcut, ipcMain, Menu, MenuItemConstructorOptions, shell} from 'electron';
import * as path from 'path';

import {EVENT_TYPE} from '../lib/eventType';
import * as locale from '../locale/locale';
import {getLogger} from '../logging/getLogger';
import {gatherLogs} from '../logging/loggerUtils';
import * as EnvironmentUtil from '../runtime/EnvironmentUtil';
import * as lifecycle from '../runtime/lifecycle';
import {config} from '../settings/config';
import {settings} from '../settings/ConfigurationPersistence';
import {SettingsType} from '../settings/SettingsType';
import {WindowManager} from '../window/WindowManager';
import {downloadLogs} from '../lib/download';
import {zipFiles, createFile} from '../lib/zip';

const launchCmd = process.env.APPIMAGE || process.execPath;

const logger = getLogger(path.basename(__filename));

const launcher = new autoLaunch({
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,7 +18,7 @@
  */
 
 import autoLaunch = require('auto-launch');
-import {dialog, globalShortcut, ipcMain, Menu, MenuItemConstructorOptions, shell} from 'electron';
+import {dialog, globalShortcut, ipcMain, Menu, MenuItemConstructorOptions} from 'electron';
 import * as path from 'path';
 
 import {EVENT_TYPE} from '../lib/eventType';
@@ -33,6 +33,7 @@
 import {WindowManager} from '../window/WindowManager';
 import {downloadLogs} from '../lib/download';
 import {zipFiles, createFile} from '../lib/zip';
+import * as WindowUtil from '../window/WindowUtil';
 
 const launchCmd = process.env.APPIMAGE || process.execPath;
 
@@ -251,23 +252,23 @@
   role: 'help',
   submenu: [
     {
-      click: () => shell.openExternal(config.legalUrl),
+      click: () => WindowUtil.openExternal(config.legalUrl, true),
       label: locale.getText('menuLegal'),
     },
     {
-      click: () => shell.openExternal(config.privacyUrl),
+      click: () => WindowUtil.openExternal(config.privacyUrl, true),
       label: locale.getText('menuPrivacy'),
     },
     {
-      click: () => shell.openExternal(config.licensesUrl),
+      click: () => WindowUtil.openExternal(config.licensesUrl, true),
       label: locale.getText('menuLicense'),
     },
     {
-      click: () => shell.openExternal(config.supportUrl),
+      click: () => WindowUtil.openExternal(config.supportUrl, true),
       label: locale.getText('menuSupport'),
     },
     {
-      click: () => shell.openExternal(EnvironmentUtil.web.getWebsiteUrl()),
+      click: () => WindowUtil.openExternal(EnvironmentUtil.web.getWebsiteUrl(), true),
       label: locale.getText('menuAppURL'),
     },
     downloadLogsTemplate,
```
