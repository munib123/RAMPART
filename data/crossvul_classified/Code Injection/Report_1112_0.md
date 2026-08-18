# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 1112_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1112_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 15-55 of the vulnerable file.

 */
/*
 * Copyright (C) 2011 The Guava Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package com.linecorp.armeria.common;

import static java.util.Objects.requireNonNull;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Map;

import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableMap;

import io.netty.util.AsciiString;

/**
 * Contains constant definitions for the HTTP header field names.
 *
 * <p>All header names in this class are defined in lowercase to support HTTP/2 requirements while
 * also not violating HTTP/1 requirements.</p>
 */
public final class HttpHeaderNames {

    // Forked from Guava 27.1 at 8e174e76971449665658a800af6dd350806cc934
    // Changes:
    // - Added pseudo headers
    // - Added Accept-Patch
    // - Added Content-Base
    // - Added Prefer
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,10 +32,12 @@
 
 import java.lang.reflect.Field;
 import java.lang.reflect.Modifier;
+import java.util.BitSet;
 import java.util.Map;
 
 import com.google.common.base.Ascii;
 import com.google.common.collect.ImmutableMap;
+import com.google.common.math.IntMath;
 
 import io.netty.util.AsciiString;
 
@@ -65,6 +67,35 @@
     //   - Sec-Fetch-User
     //   - Sec-Metadata
 
+    private static final int PROHIBITED_NAME_CHAR_MASK = ~63;
+    private static final BitSet PROHIBITED_NAME_CHARS = new BitSet(~PROHIBITED_NAME_CHAR_MASK + 1);
+    private static final String[] PROHIBITED_NAME_CHAR_NAMES = new String[~PROHIBITED_NAME_CHAR_MASK + 1];
+
+    static {
+        PROHIBITED_NAME_CHARS.set(0);
+        PROHIBITED_NAME_CHARS.set('\t');
+        PROHIBITED_NAME_CHARS.set('\n');
+        PROHIBITED_NAME_CHARS.set(0xB);
+        PROHIBITED_NAME_CHARS.set('\f');
+        PROHIBITED_NAME_CHARS.set('\r');
+        PROHIBITED_NAME_CHARS.set(' ');
+        PROHIBITED_NAME_CHARS.set(',');
+        PROHIBITED_NAME_CHARS.set(':');
+        PROHIBITED_NAME_CHARS.set(';');
+        PROHIBITED_NAME_CHARS.set('=');
+        PROHIBITED_NAME_CHAR_NAMES[0] = "<NUL>";
+        PROHIBITED_NAME_CHAR_NAMES['\t'] = "<TAB>";
+        PROHIBITED_NAME_CHAR_NAMES['\n'] = "<LF>";
+        PROHIBITED_NAME_CHAR_NAMES[0xB] = "<VT>";
+        PROHIBITED_NAME_CHAR_NAMES['\f'] = "<FF>";
+        PROHIBITED_NAME_CHAR_NAMES['\r'] = "<CR>";
+        PROHIBITED_NAME_CHAR_NAMES[' '] = "<SP>";
+        PROHIBITED_NAME_CHAR_NAMES[','] = ",";
+        PROHIBITED_NAME_CHAR_NAMES[':'] = ":";
+        PROHIBITED_NAME_CHAR_NAMES[';'] = ";";
+        PROHIBITED_NAME_CHAR_NAMES['='] = "=";
+    }
+
     // Pseudo-headers
 
     /**
@@ -564,10 +595,16 @@
         map = builder.build();
     }
 
+    private static AsciiString create(String name) {
+        return AsciiString.cached(Ascii.toLowerCase(name));
+    }
+
     /**
      * Lower-cases and converts the specified header name into an {@link AsciiString}. If {@code "name"} is
      * a known header name, this method will return a pre-instantiated {@link AsciiString} to reduce
      * the allocation rate of {@link AsciiString}.
+     *
+     * @throws IllegalArgumentException if the specified {@code name} is not a valid header name.
      */
     public static AsciiString of(CharSequence name) {
         if (name instanceof AsciiString) {
@@ -576,22 +613,71 @@
 
         final String lowerCased = Ascii.toLowerCase(requireNonNull(name, "name"));
         final AsciiString cached = map.get(lowerCased);
-        return cached != null ? cached : AsciiString.cached(lowerCased);
+        if (cached != null) {
+            return cached;
+        }
+
+        return validate(AsciiString.cached(lowerCased));
     }
 
     /**
      * Lower-cases and converts the specified header name into an {@link AsciiString}. If {@code "name"} is
      * a known header name, this method will return a pre-instantiated {@link AsciiString} to reduce
      * the allocation rate of {@link AsciiString}.
+     *
+     * @throws IllegalArgumentException if the specified {@code name} is not a valid header name.
      */
     public static AsciiString of(AsciiString name) {
         final AsciiString lowerCased = name.toLowerCase();
         final AsciiString cached = map.get(lowerCased);
-        return cached != null ? cached : lowerCased;
+        if (cached != null) {
+            return cached;
+        }
+
+        return validate(lowerCased);
     }
 
-    private static AsciiString create(String name) {
-        return AsciiString.cached(Ascii.toLowerCase(name));
+    private static AsciiString validate(AsciiString name) {
+        if (name.isEmpty()) {
+            throw new IllegalArgumentException("malformed header name: <EMPTY>");
+        }
+
+        final int lastIndex;
+        try {
+            lastIndex = name.forEachByte(value -> {
+                if ((value & PROHIBITED_NAME_CHAR_MASK) != 0) { // value >= 64
+                    return true;
+                }
+
+                // value < 64
+                return !PROHIBITED_NAME_CHARS.get(value);
+            });
+        } catch (Exception e) {
+            throw new Error(e);
+        }
+
+        if (lastIndex >= 0) {
+            throw new IllegalArgumentException(malformedHeaderNameMessage(name));
+        }
+
+        return name;
+    }
+
+    private static String malformedHeaderNameMessage(AsciiString name) {
+        final StringBuilder buf = new StringBuilder(IntMath.saturatedAdd(name.length(), 64));
+        buf.append("malformed header name: ");
+
+        final int nameLength = name.length();
+        for (int i = 0; i < nameLength; i++) {
+            final char ch = name.charAt(i);
+            if (PROHIBITED_NAME_CHARS.get(ch)) {
+                buf.append(PROHIBITED_NAME_CHAR_NAMES[ch]);
+            } else {
+                buf.append(ch);
+            }
+        }
+
+        return buf.toString();
     }
 
     private HttpHeaderNames() {}
```
