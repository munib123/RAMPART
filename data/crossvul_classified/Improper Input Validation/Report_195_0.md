# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 195_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `195_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 1-33 of the vulnerable file.

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

package io.vertx.core.http;

/**
 * Contains often used Header names.
 * <p>
 * It also contains a utility method to create optimized {@link CharSequence} which can be used as header name and value.
 *
 * @author <a href="mailto:nmaurer@redhat.com">Norman Maurer</a>
 */
public final class HttpHeaders {


  /**
   * Accept header name
   */
  public static final CharSequence ACCEPT = createOptimized(io.netty.handler.codec.http.HttpHeaders.Names.ACCEPT);

  /**
   * Accept-Charset header name
   */
  public static final CharSequence ACCEPT_CHARSET = createOptimized(io.netty.handler.codec.http.HttpHeaders.Names.ACCEPT_CHARSET);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,6 +11,9 @@
 
 package io.vertx.core.http;
 
+import io.netty.util.AsciiString;
+import io.vertx.core.http.impl.HttpUtils;
+
 /**
  * Contains often used Header names.
  * <p>
@@ -324,7 +327,8 @@
    * for multiple responses or requests.
    */
   public static CharSequence createOptimized(String value) {
-    return io.netty.handler.codec.http.HttpHeaders.newEntity(value);
+    HttpUtils.validateHeader(value);
+    return new AsciiString(value);
   }
 
   private HttpHeaders() {
```
