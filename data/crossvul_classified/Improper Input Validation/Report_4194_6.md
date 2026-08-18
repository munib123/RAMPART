# CrossVul Fix Pair: Improper Input Validation in typescript
**Pair ID:** 4194_6
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4194_6`)

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

import {BrowserWindow, screen} from 'electron';

interface Rectangle {
  height: number;
  width: number;
  x: number;
  y: number;
}

export const pointInRectangle = (point: [number, number], rectangle: Rectangle): boolean => {
  const [x, y] = point;
  const xInRange = x >= rectangle.x && x <= rectangle.x + rectangle.width;
  const yInRange = y >= rectangle.y && y <= rectangle.y + rectangle.height;

  return xInRange && yInRange;
};

export const isInView = (win: BrowserWindow): boolean => {
  const windowBounds = win.getBounds();
  const nearestWorkArea = screen.getDisplayMatching(windowBounds).workArea;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,7 +17,14 @@
  *
  */
 
-import {BrowserWindow, screen} from 'electron';
+import {BrowserWindow, screen, shell} from 'electron';
+import * as path from 'path';
+import * as URL from 'url';
+
+import {getLogger} from '../logging/getLogger';
+import {showWarningDialog} from '../lib/showDialog';
+
+const logger = getLogger(path.basename(__filename));
 
 interface Rectangle {
   height: number;
@@ -46,3 +53,24 @@
 
   return upperLeftVisible || lowerRightVisible;
 };
+
+export const openExternal = async (url: string, httpsOnly: boolean = false): Promise<void> => {
+  try {
+    const urlProtocol = URL.parse(url).protocol || '';
+    const allowedProtocols = ['https:'];
+
+    if (!httpsOnly) {
+      allowedProtocols.push('ftp:', 'http:', 'mailto:');
+    }
+
+    if (!allowedProtocols.includes(urlProtocol)) {
+      logger.warn(`Prevented opening external URL "${url}".`);
+      showWarningDialog(`Prevented opening external URL "${url}".`);
+      return;
+    }
+
+    await shell.openExternal(url);
+  } catch (error) {
+    logger.error(error);
+  }
+};
```
