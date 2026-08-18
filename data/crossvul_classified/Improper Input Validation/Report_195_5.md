# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 195_5
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `195_5`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 1-38 of the vulnerable file.

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

package io.vertx.core.http.impl.headers;

import io.netty.handler.codec.http.HttpHeaders;
import io.netty.util.AsciiString;
import io.netty.util.HashingStrategy;
import io.vertx.core.MultiMap;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;

import static io.netty.util.AsciiString.*;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
public final class VertxHttpHeaders extends HttpHeaders implements MultiMap {

  @Override
  public MultiMap setAll(MultiMap headers) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,6 +15,7 @@
 import io.netty.util.AsciiString;
 import io.netty.util.HashingStrategy;
 import io.vertx.core.MultiMap;
+import io.vertx.core.http.impl.HttpUtils;
 
 import java.util.AbstractMap;
 import java.util.ArrayList;
@@ -54,7 +55,7 @@
   }
 
   private final VertxHttpHeaders.MapEntry[] entries = new VertxHttpHeaders.MapEntry[16];
-  private final VertxHttpHeaders.MapEntry head = new VertxHttpHeaders.MapEntry(-1, null, null);
+  private final VertxHttpHeaders.MapEntry head = new VertxHttpHeaders.MapEntry();
 
   public VertxHttpHeaders() {
     head.before = head.after = head;
@@ -397,6 +398,12 @@
     VertxHttpHeaders.MapEntry next;
     VertxHttpHeaders.MapEntry before, after;
 
+    MapEntry() {
+      this.hash = -1;
+      this.key = null;
+      this.value = null;
+    }
+
     MapEntry(int hash, CharSequence key, CharSequence value) {
       this.hash = hash;
       this.key = key;
@@ -476,6 +483,12 @@
   }
 
   private void add0(int h, int i, final CharSequence name, final CharSequence value) {
+    if (!(name instanceof AsciiString)) {
+      HttpUtils.validateHeader(name);
+    }
+    if (!(value instanceof AsciiString)) {
+      HttpUtils.validateHeader(value);
+    }
     // Update the hash table.
     VertxHttpHeaders.MapEntry e = entries[i];
     VertxHttpHeaders.MapEntry newEntry;
```
