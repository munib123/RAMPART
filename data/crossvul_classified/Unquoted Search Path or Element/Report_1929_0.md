# CrossVul Fix Pair: Unquoted Search Path or Element in java
**Pair ID:** 1929_0
**Vulnerability Class:** Unquoted Search Path or Element
**CWE:** CWE-428
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1929_0`)

## Vulnerability Information & PoC

## Description
Unquoted Search Path or Element - If a malicious individual has access to the file system, it is possible to elevate privileges by inserting such a file as C:Program.

## Vulnerable Code
```java
Lines 1-22 of the vulnerable file.

/*
 * Copyright 2018 Anton Tananaev (anton@traccar.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.Winsvc;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /*
- * Copyright 2018 Anton Tananaev (anton@traccar.org)
+ * Copyright 2018 - 2020 Anton Tananaev (anton@traccar.org)
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -50,7 +50,7 @@
             String account, String password, String config) throws URISyntaxException {
 
         String javaHome = System.getProperty("java.home");
-        String javaBinary = javaHome + "\\bin\\java.exe";
+        String javaBinary = "\"" + javaHome + "\\bin\\java.exe\"";
 
         File jar = new File(WindowsService.class.getProtectionDomain().getCodeSource().getLocation().toURI());
         String command = javaBinary
```
