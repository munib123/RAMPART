# CrossVul Fix Pair: Incorrect Authorization in java
**Pair ID:** 4545_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4545_1`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```java
Lines 1-36 of the vulnerable file.

/**
 * Copyright (c) 2010-2020 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.exec.internal;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.smarthome.core.thing.ThingTypeUID;

/**
 * The {@link ExecBinding} class defines common constants, which are
 * used across the whole binding.
 *
 * @author Karel Goderis - Initial contribution
 */
@NonNullByDefault
public class ExecBindingConstants {

    public static final String BINDING_ID = "exec";

    // List of all Thing Type UIDs
    public static final ThingTypeUID THING_COMMAND = new ThingTypeUID(BINDING_ID, "command");

    // List of all Channel ids
    public static final String OUTPUT = "output";
    public static final String INPUT = "input";
    public static final String EXIT = "exit";
    public static final String RUN = "run";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,17 +13,19 @@
 package org.openhab.binding.exec.internal;
 
 import org.eclipse.jdt.annotation.NonNullByDefault;
+import org.eclipse.smarthome.config.core.ConfigConstants;
 import org.eclipse.smarthome.core.thing.ThingTypeUID;
 
+import java.io.File;
+
 /**
- * The {@link ExecBinding} class defines common constants, which are
+ * The {@link ExecBindingConstants} class defines common constants, which are
  * used across the whole binding.
  *
  * @author Karel Goderis - Initial contribution
  */
 @NonNullByDefault
 public class ExecBindingConstants {
-
     public static final String BINDING_ID = "exec";
 
     // List of all Thing Type UIDs
@@ -35,5 +37,4 @@
     public static final String EXIT = "exit";
     public static final String RUN = "run";
     public static final String LAST_EXECUTION = "lastexecution";
-
 }
```
