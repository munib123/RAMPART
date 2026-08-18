# CrossVul Fix Pair: Improper Input Validation in typescript
**Pair ID:** 4194_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4194_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```typescript
Lines 1-33 of the vulnerable file.

/*
 * Wire
 * Copyright (C) 2020 Wire Swiss GmbH
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

import {dialog, MessageBoxSyncOptions} from 'electron';

export const showDialog = (message: string, title: string, type?: string): void => {
  const options: MessageBoxSyncOptions = {
    message,
    title,
    type,
  };
  dialog.showMessageBoxSync(options);
};

export const showErrorDialog = (message: string): void => {
  showDialog(message, 'Error', 'error');
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,6 +18,7 @@
  */
 
 import {dialog, MessageBoxSyncOptions} from 'electron';
+import * as locale from '../locale/locale';
 
 export const showDialog = (message: string, title: string, type?: string): void => {
   const options: MessageBoxSyncOptions = {
@@ -31,3 +32,13 @@
 export const showErrorDialog = (message: string): void => {
   showDialog(message, 'Error', 'error');
 };
+
+export const showWarningDialog = (message: string): void => {
+  const options: MessageBoxSyncOptions = {
+    buttons: ['OK'],
+    message,
+    title: 'Warning',
+    type: 'warning',
+  };
+  dialog.showMessageBoxSync(options);
+};
```
