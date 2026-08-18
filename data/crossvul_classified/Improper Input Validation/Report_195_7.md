# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 195_7
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `195_7`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 1-26 of the vulnerable file.

/*
 * Copyright (c) 2011-2017 Contributors to the Eclipse Foundation
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */

package io.vertx.test.core;

import io.vertx.core.MultiMap;
import io.vertx.core.http.impl.headers.VertxHttpHeaders;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
public class VertxHttpHeadersTest extends CaseInsensitiveHeadersTest {

  @Override
  protected MultiMap newMultiMap() {
    return new VertxHttpHeaders();
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,7 @@
 
 import io.vertx.core.MultiMap;
 import io.vertx.core.http.impl.headers.VertxHttpHeaders;
+import org.junit.Test;
 
 /**
  * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
@@ -23,4 +24,9 @@
   protected MultiMap newMultiMap() {
     return new VertxHttpHeaders();
   }
+
+  @Override
+  public void testHashMININT() {
+    // Does not apply
+  }
 }
```
