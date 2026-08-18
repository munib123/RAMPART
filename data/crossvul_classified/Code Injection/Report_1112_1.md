# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 1112_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1112_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 12-52 of the vulnerable file.

 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright 2014 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License, version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at:
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package com.linecorp.armeria.common;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;
import static com.linecorp.armeria.internal.ArmeriaHttpUtil.isAbsoluteUri;
import static io.netty.handler.codec.http2.Http2Headers.PseudoHeaderName.hasPseudoHeaderFormat;
import static io.netty.util.internal.MathUtil.findNextPositivePowerOfTwo;
import static java.lang.Math.max;
import static java.lang.Math.min;
import static java.util.Objects.requireNonNull;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiConsumer;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,7 +29,6 @@
  */
 package com.linecorp.armeria.common;
 
-import static com.google.common.base.Preconditions.checkArgument;
 import static com.google.common.base.Preconditions.checkState;
 import static com.linecorp.armeria.internal.ArmeriaHttpUtil.isAbsoluteUri;
 import static io.netty.handler.codec.http2.Http2Headers.PseudoHeaderName.hasPseudoHeaderFormat;
@@ -41,6 +40,7 @@
 import java.net.URI;
 import java.net.URISyntaxException;
 import java.util.Arrays;
+import java.util.BitSet;
 import java.util.Date;
 import java.util.Iterator;
 import java.util.List;
@@ -58,6 +58,7 @@
 import com.google.common.collect.ImmutableList;
 import com.google.common.collect.ImmutableSet;
 import com.google.common.collect.Iterators;
+import com.google.common.math.IntMath;
 
 import io.netty.handler.codec.DateFormatter;
 import io.netty.util.AsciiString;
@@ -66,6 +67,23 @@
  * The base container implementation of HTTP/2 headers.
  */
 class HttpHeadersBase implements HttpHeaderGetters {
+
+    private static final int PROHIBITED_VALUE_CHAR_MASK = ~15;
+    private static final BitSet PROHIBITED_VALUE_CHARS = new BitSet(~PROHIBITED_VALUE_CHAR_MASK + 1);
+    private static final String[] PROHIBITED_VALUE_CHAR_NAMES = new String[~PROHIBITED_VALUE_CHAR_MASK + 1];
+
+    static {
+        PROHIBITED_VALUE_CHARS.set(0);
+        PROHIBITED_VALUE_CHARS.set('\n');
+        PROHIBITED_VALUE_CHARS.set(0xB);
+        PROHIBITED_VALUE_CHARS.set('\f');
+        PROHIBITED_VALUE_CHARS.set('\r');
+        PROHIBITED_VALUE_CHAR_NAMES[0] = "<NUL>";
+        PROHIBITED_VALUE_CHAR_NAMES['\n'] = "<LF>";
+        PROHIBITED_VALUE_CHAR_NAMES[0xB] = "<VT>";
+        PROHIBITED_VALUE_CHAR_NAMES['\f'] = "<FF>";
+        PROHIBITED_VALUE_CHAR_NAMES['\r'] = "<CR>";
+    }
 
     static final int DEFAULT_SIZE_HINT = 16;
 
@@ -545,7 +563,7 @@
     }
 
     final void add(CharSequence name, String value) {
-        final AsciiString normalizedName = normalizeName(name);
+        final AsciiString normalizedName = HttpHeaderNames.of(name);
         requireNonNull(value, "value");
         final int h = normalizedName.hashCode();
         final int i = index(h);
@@ -553,7 +571,7 @@
     }
 
     final void add(CharSequence name, Iterable<String> values) {
-        final AsciiString normalizedName = normalizeName(name);
+        final AsciiString normalizedName = HttpHeaderNames.of(name);
         requireNonNull(values, "values");
         final int h = normalizedName.hashCode();
         final int i = index(h);
@@ -564,7 +582,7 @@
     }
 
     final void add(CharSequence name, String... values) {
-        final AsciiString normalizedName = normalizeName(name);
+        final AsciiString normalizedName = HttpHeaderNames.of(name);
         requireNonNull(values, "values");
         final int h = normalizedName.hashCode();
         final int i = index(h);
@@ -590,7 +608,7 @@
     }
 
     final void addObject(CharSequence name, Iterable<?> values) {
-        final AsciiString normalizedName = normalizeName(name);
+        final AsciiString normalizedName = HttpHeaderNames.of(name);
         requireNonNull(values, "values");
         for (Object v : values) {
             requireNonNullElement(values, v);
@@ -599,7 +617,7 @@
     }
 
     final void addObject(CharSequence name, Object... values) {
-        final AsciiString normalizedName = normalizeName(name);
+        final AsciiString normalizedName = HttpHeaderNames.of(name);
         requireNonNull(values, "values");
         for (Object v : values) {
             requireNonNullElement(values, v);
@@ -638,7 +656,7 @@
     }
 
     final void set(CharSequence name, String value) {
-        final AsciiString normalizedName = normalizeName(name);
+        final AsciiString normalizedName = HttpHeaderNames.of(name);
         requireNonNull(value, "value");
         final int h = normalizedName.hashCode();
         final int i = index(h);
@@ -647,7 +665,7 @@
     }
 
     final void set(CharSequence name, Iterable<String> values) {
-        final AsciiString normalizedName = normalizeName(name);
+        final AsciiString normalizedName = HttpHeaderNames.of(name);
         requireNonNull(values, "values");
 
         final int h = normalizedName.hashCode();
@@ -661,7 +679,7 @@
     }
 
     final void set(CharSequence name, String... values) {
-        final AsciiString normalizedName = normalizeName(name);
+        final AsciiString normalizedName = HttpHeaderNames.of(name);
         requireNonNull(values, "values");
 
         final int h = normalizedName.hashCode();
@@ -739,7 +757,7 @@
     }
 
     final void setObject(CharSequence name, Iterable<?> values) {
-        final AsciiString normalizedName = normalizeName(name);
+        final AsciiString normalizedName = HttpHeaderNames.of(name);
         requireNonNull(values, "values");
 
         final int h = normalizedName.hashCode();
@@ -753,7 +771,7 @@
     }
 
     final void setObject(CharSequence name, Object... values) {
-        final AsciiString normalizedName = normalizeName(name);
+        final AsciiString normalizedName = HttpHeaderNames.of(name);
         requireNonNull(values, "values");
 
         final int h = normalizedName.hashCode();
@@ -813,11 +831,6 @@
         size = 0;
     }
 
-    private static AsciiString normalizeName(CharSequence name) {
-        checkArgument(requireNonNull(name, "name").length() > 0, "name is empty.");
-        return HttpHeaderNames.of(name);
-    }
-
     private static void requireNonNullElement(Object values, @Nullable Object e) {
         if (e == null) {
             throw new NullPointerException("values contains null: " + values);
@@ -829,9 +842,42 @@
     }
 
     private void add0(int h, int i, AsciiString name, String value) {
+        validateValue(value);
         // Update the hash table.
         entries[i] = new HeaderEntry(h, name, value, entries[i]);
         ++size;
+    }
+
+    private static void validateValue(String value) {
+        final int valueLength = value.length();
+        for (int i = 0; i < valueLength; i++) {
+            final char ch = value.charAt(i);
+            if ((ch & PROHIBITED_VALUE_CHAR_MASK) != 0) { // ch >= 16
+                continue;
+            }
+
+            // ch < 16
+            if (PROHIBITED_VALUE_CHARS.get(ch)) {
+                throw new IllegalArgumentException(malformedHeaderValueMessage(value));
+            }
+        }
+    }
+
+    private static String malformedHeaderValueMessage(String value) {
+        final StringBuilder buf = new StringBuilder(IntMath.saturatedAdd(value.length(), 64));
+        buf.append("malformed header value: ");
+
+        final int valueLength = value.length();
+        for (int i = 0; i < valueLength; i++) {
+            final char ch = value.charAt(i);
+            if (PROHIBITED_VALUE_CHARS.get(ch)) {
+                buf.append(PROHIBITED_VALUE_CHAR_NAMES[ch]);
+            } else {
+                buf.append(ch);
+            }
+        }
+
+        return buf.toString();
     }
 
     private boolean addFast(Iterable<? extends Entry<? extends CharSequence, ?>> headers) {
```
