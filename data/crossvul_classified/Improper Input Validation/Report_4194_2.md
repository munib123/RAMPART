# CrossVul Fix Pair: Improper Input Validation in typescript
**Pair ID:** 4194_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4194_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```typescript
Lines 11-51 of the vulnerable file.

 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

import {LogFactory} from '@wireapp/commons';
import {
  app,
  BrowserWindow,
  BrowserWindowConstructorOptions,
  Event as ElectronEvent,
  Filter,
  HeadersReceivedResponse,
  ipcMain,
  Menu,
  OnHeadersReceivedListenerDetails,
  shell,
  WebContents,
} from 'electron';
import * as fs from 'fs-extra';
import {getProxySettings} from 'get-proxy-settings';
import * as logdown from 'logdown';
import * as minimist from 'minimist';
import * as path from 'path';
import {URL} from 'url';
import windowStateKeeper = require('electron-window-state');
import fileUrl = require('file-url');

import './global';
import {
  attachTo as attachCertificateVerifyProcManagerTo,
  setCertificateVerifyProc,
} from './lib/CertificateVerifyProcManager';
import {CustomProtocolHandler} from './lib/CoreProtocol';
import {downloadImage} from './lib/download';
import {EVENT_TYPE} from './lib/eventType';
import {deleteAccount} from './lib/LocalAccountDeletion';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,7 +28,6 @@
   ipcMain,
   Menu,
   OnHeadersReceivedListenerDetails,
-  shell,
   WebContents,
 } from 'electron';
 import * as fs from 'fs-extra';
@@ -264,7 +263,7 @@
       return;
     }
 
-    await shell.openExternal(url);
+    return WindowUtil.openExternal(url);
   });
 
   main.on('focus', () => {
@@ -507,7 +506,7 @@
       }
 
       this.logger.log('Opening an external window from a webview.');
-      return shell.openExternal(url);
+      return WindowUtil.openExternal(url);
     };
 
     const willNavigateInWebview = (event: ElectronEvent, url: string, baseUrl: string): void => {
```
