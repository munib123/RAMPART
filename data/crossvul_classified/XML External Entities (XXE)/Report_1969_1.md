# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1969_1
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1969_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 1-39 of the vulnerable file.

// Copyright (C) 2012 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.json;

import static com.google.json.JsonSanitizer.DEFAULT_NESTING_DEPTH;
import static com.google.json.JsonSanitizer.sanitize;
import java.util.logging.Level;
import java.util.logging.Logger;
import junit.framework.TestCase;
import org.junit.Test;

@SuppressWarnings("javadoc")
public final class JsonSanitizerTest extends TestCase {

  private static void assertSanitized(String golden, String input) {
    assertSanitized(golden, input, DEFAULT_NESTING_DEPTH);
  }

  private static void assertSanitized(String golden, String input, int maximumNestingDepth) {
    String actual = sanitize(input, maximumNestingDepth);
    assertEquals(input, golden, actual);
    if (actual.equals(input)) {
      assertSame(input, input, actual);
    }
  }

  private static void assertSanitized(String sanitary) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,6 +16,8 @@
 
 import static com.google.json.JsonSanitizer.DEFAULT_NESTING_DEPTH;
 import static com.google.json.JsonSanitizer.sanitize;
+
+import java.util.Locale;
 import java.util.logging.Level;
 import java.util.logging.Logger;
 import junit.framework.TestCase;
@@ -198,7 +200,7 @@
   }
 
   @Test
-  public static final void testClosedArray() {
+  public static final void testUnopenedArray() {
     // Discovered by fuzzer with seed -Dfuzz.seed=df3b4778ce54d00a
     assertSanitized("-1742461140214282", "\ufeff-01742461140214282]");
   }
@@ -228,4 +230,102 @@
 
     assertSanitized("\"\\u003c!--\\u003cscript>\"", "\"<!--<script>\"");
   }
+
+  @Test
+  public static final void testLongOctalNumberWithBadDigits() {
+    // Found by Fabian Meumertzheim using CI Fuzz (https://www.code-intelligence.com)
+    assertEquals(
+            "-888888888888888888888",
+            JsonSanitizer.sanitize("-0888888888888888888888")
+    );
+  }
+
+  @Test
+  public static final void testLongNumberInUnclosedInputWithU80() {
+    // Found by Fabian Meumertzheim using CI Fuzz (https://www.code-intelligence.com)
+    assertEquals(
+            "{\"\":{\"\":{\"\":{\"\":{\"\":{\"\":{\"x80\":{\"\":{\"\":[-400557869725698078427]}}}}}}}}}",
+            JsonSanitizer.sanitize("{{{{{{{\\x80{{([-053333333304233333333333")
+    );
+  }
+
+  @Test
+  public static final void testSlashFour() {
+    // Found by Fabian Meumertzheim using CI Fuzz (https://www.code-intelligence.com)
+    assertEquals("\"y\\u0004\"", JsonSanitizer.sanitize("y\\4")); // "y\4"
+  }
+
+  @Test
+  public static final void testUnterminatedObject() {
+    // Found by Fabian Meumertzheim using CI Fuzz (https://www.code-intelligence.com)
+    String input = "?\u0000\u0000\u0000{{\u0000\ufffd\u0003]ve{R]\u00000\ufffd\u0016&e{\u0003]\ufffda<!.b<!<!cc1x\u0000\u00005{281<\u0000.{t\u0001\ufffd5\ufffd{5\ufffd\ufffd0\ufffd15\r\ufffd\u0000\u0000\u0000~~-0081273222428822883223759,55\ufffd\u0000\ufffd\t\u0000\ufffd";
+    String got = JsonSanitizer.sanitize(input);
+    String want = "{\"\":{},\"ve\":{\"R\":null},\"0\":\"e\",\"\":{},\"a<!.b<!<!cc1x\":5,\"\":{\"281\":0.0,\"\":{\"t\":5,\"\":{\"5\":0,\"15\"\r:-81273222428822883223759,\"55\"\t:null}}}}";
+    assertEquals(want, got);
+  }
+
+  @Test
+  public static final void testCrash1() {
+    // Found by Fabian Meumertzheim using CI Fuzz (https://www.code-intelligence.com)
+    String input = "?\u0000\u0000\u0000{{\u0000\ufffd\u0003]ve{R]\u00000\ufffd\ufffd\u0016&e{\u0003]\ufffda<!.b<!<!c\u00005{281<\u0000.{t\u0001\ufffd5\ufffd{515\r[\u0000\u0000\u0000~~-008127322242\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd23759,551x\u0000\u00006{281<\u0000.{t\u0001\ufffd5\ufffd{5\ufffd\ufffd0\ufffd15\r[\u0000\u0000\u0000~~-0081273222428822883223759,\ufffd";
+    String want = "{\"\":{},\"ve\":{\"R\":null},\"0\":\"e\",\"\":{},\"a<!.b<!<!c\":5,\"\":{\"281\":0.0,\"\":{\"t\":5,\"\":{\"515\"\r:[-8127322242,23759,551,6,{\"281\":0.0,\"\":{\"t\":5,\"\":{\"5\":0,\"15\"\r:[-81273222428822883223759]}}}]}}}}";
+    String got = JsonSanitizer.sanitize(input);
+    assertEquals(want, got);
+  }
+
+  @Test
+  public static final void testDisallowedSubstrings() {
+    // Found by Fabian Meumertzheim using CI Fuzz (https://www.code-intelligence.com)
+    String[] inputs = {
+            "x<\\script>",
+            "x</\\script>",
+            "x</sc\\ript>",
+            "x<\\163cript>",
+            "x</\\163cript>",
+            "x<\\123cript>",
+            "x</\\123cript>",
+            "u\\u\\uu\ufffd\ufffd\\u7u\\u\\u\\u\ufffdu<\\script>5",
+            "z\\<\\!--",
+            "z\\<!\\--",
+            "z\\<!-\\-",
+            "z\\<\\!--",
+            "\"\\]]\\>",
+    };
+    for (String input : inputs) {
+      String out = JsonSanitizer.sanitize(input).toLowerCase(Locale.ROOT);
+      assertFalse(out, out.contains("<!--"));
+      assertFalse(out, out.contains("-->"));
+      assertFalse(out, out.contains("<script"));
+      assertFalse(out, out.contains("</script"));
+      assertFalse(out, out.contains("]]>"));
+      assertFalse(out, out.contains("<![cdata["));
+    }
+  }
+
+  @Test
+  public static final void testXssPayload() {
+    // Found by Fabian Meumertzheim using CI Fuzz (https://www.code-intelligence.com)
+    String input = "x</\\script>u\\u\\uu\ufffd\ufffd\\u7u\\u\\u\\u\ufffdu<\\script>5+alert(1)//";
+    assertEquals(
+            "\"x\\u003c/script>uuuu\uFFFD\uFFFDu7uuuu\uFFFDu\\u003cscript>5+alert(1)//\"",
+            JsonSanitizer.sanitize(input)
+    );
+  }
+
+  @Test
+  public static final void testInvalidOutput() {
+    // Found by Fabian Meumertzheim using CI Fuzz (https://www.code-intelligence.com)
+    String input = "\u0010{'\u0000\u0000'\"\u0000\"{.\ufffd-0X29295909049550970,\n\n0";
+    String want = "{\"\\u0000\\u0000\":\"\\u0000\",\"\":{\"0\":-47455995597866469744,\n\n\"0\":null}}";
+    String got = JsonSanitizer.sanitize(input);
+    assertEquals(want, got);
+  }
+
+  @Test
+  public static final void testBadNumber() {
+    String input = "¶0x.\\蹃4\\À906";
+    String want = "0.0";
+    String got = JsonSanitizer.sanitize(input);
+    assertEquals(want, got);
+  }
 }
```
