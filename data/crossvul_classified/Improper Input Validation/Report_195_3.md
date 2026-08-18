# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 195_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `195_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 1-40 of the vulnerable file.

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

package io.vertx.core.http.impl;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.CompositeByteBuf;
import io.netty.buffer.Unpooled;
import io.vertx.codegen.annotations.Nullable;
import io.vertx.core.*;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.CaseInsensitiveHeaders;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpConnection;
import io.vertx.core.http.HttpFrame;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpVersion;
import io.vertx.core.impl.ContextInternal;
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.core.net.NetSocket;

import java.util.List;
import java.util.Objects;

import static io.vertx.core.http.HttpHeaders.*;

/**
 * This class is optimised for performance when used on the same event loop that is was passed to the handler with.
 * However it can be used safely from other threads.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,13 +17,13 @@
 import io.vertx.codegen.annotations.Nullable;
 import io.vertx.core.*;
 import io.vertx.core.buffer.Buffer;
-import io.vertx.core.http.CaseInsensitiveHeaders;
 import io.vertx.core.http.HttpClientRequest;
 import io.vertx.core.http.HttpClientResponse;
 import io.vertx.core.http.HttpConnection;
 import io.vertx.core.http.HttpFrame;
 import io.vertx.core.http.HttpMethod;
 import io.vertx.core.http.HttpVersion;
+import io.vertx.core.http.impl.headers.VertxHttpHeaders;
 import io.vertx.core.impl.ContextInternal;
 import io.vertx.core.impl.VertxInternal;
 import io.vertx.core.logging.Logger;
@@ -68,7 +68,7 @@
   private int pendingMaxSize = -1;
   private int followRedirects;
   private long written;
-  private CaseInsensitiveHeaders headers;
+  private VertxHttpHeaders headers;
 
   private HttpClientStream stream;
   private boolean connecting;
@@ -183,7 +183,7 @@
   @Override
   public synchronized MultiMap headers() {
     if (headers == null) {
-      headers = new CaseInsensitiveHeaders();
+      headers = new VertxHttpHeaders();
     }
     return headers;
   }
```
