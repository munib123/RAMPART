# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in java
**Pair ID:** 853_3
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `853_3`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```java
Lines 2-42 of the vulnerable file.

 * Copyright (c) Facebook, Inc. and its affiliates.
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

package com.facebook.thrift;

import com.facebook.thrift.java.test.MyListStruct;
import com.facebook.thrift.java.test.MyMapStruct;
import com.facebook.thrift.java.test.MySetStruct;
import com.facebook.thrift.protocol.TBinaryProtocol;
import com.facebook.thrift.protocol.TCompactProtocol;
import com.facebook.thrift.protocol.TProtocol;
import com.facebook.thrift.protocol.TProtocolException;
import com.facebook.thrift.protocol.TType;
import com.facebook.thrift.transport.TMemoryInputTransport;
import org.junit.Test;

public class TruncatedFrameTest extends junit.framework.TestCase {
  private static final byte[] kBinaryListEncoding = {
    TType.LIST, // Field Type = List
    (byte) 0x00,
    (byte) 0x01, // Field id = 1
    TType.I64, // List type = i64
    (byte) 0x00,
    (byte) 0x00,
    (byte) 0x00,
    (byte) 0xFF, // List length (255 > 3!)
    (byte) 0x00,
    (byte) 0x00,
    (byte) 0x00,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,7 @@
 import com.facebook.thrift.java.test.MyListStruct;
 import com.facebook.thrift.java.test.MyMapStruct;
 import com.facebook.thrift.java.test.MySetStruct;
+import com.facebook.thrift.java.test.MyStringStruct;
 import com.facebook.thrift.protocol.TBinaryProtocol;
 import com.facebook.thrift.protocol.TCompactProtocol;
 import com.facebook.thrift.protocol.TProtocol;
@@ -52,15 +53,15 @@
     (byte) 0x00,
     (byte) 0x00,
     (byte) 0x00,
-    (byte) 0x01, // value = 2L
-    (byte) 0x00,
-    (byte) 0x00,
-    (byte) 0x00,
-    (byte) 0x00,
-    (byte) 0x00,
-    (byte) 0x00,
-    (byte) 0x00,
-    (byte) 0x01, // value = 3L
+    (byte) 0x02, // value = 2L
+    (byte) 0x00,
+    (byte) 0x00,
+    (byte) 0x00,
+    (byte) 0x00,
+    (byte) 0x00,
+    (byte) 0x00,
+    (byte) 0x00,
+    (byte) 0x03, // value = 3L
     (byte) 0x00, // Stop
   };
 
@@ -139,15 +140,15 @@
     (byte) 0x00,
     (byte) 0x00,
     (byte) 0x00,
-    (byte) 0x01, // value = 2L
-    (byte) 0x00,
-    (byte) 0x00,
-    (byte) 0x00,
-    (byte) 0x00,
-    (byte) 0x00,
-    (byte) 0x00,
-    (byte) 0x00,
-    (byte) 0x01, // value = 3L
+    (byte) 0x02, // value = 2L
+    (byte) 0x00,
+    (byte) 0x00,
+    (byte) 0x00,
+    (byte) 0x00,
+    (byte) 0x00,
+    (byte) 0x00,
+    (byte) 0x00,
+    (byte) 0x03, // value = 3L
     (byte) 0x00, // Stop
   };
 
@@ -273,16 +274,61 @@
     testTruncated(new MyMapStruct(), iprot);
   }
 
-  private static final char[] hexArray = "0123456789ABCDEF".toCharArray();
-
-  private static String bytesToHex(byte[] bytes, int length) {
-    String out = "";
-    for (int j = 0; j < length; j++) {
-      int v = bytes[j] & 0xFF;
-      out += hexArray[v >>> 4];
-      out += hexArray[v & 0x0F];
-      out += " ";
-    }
-    return out;
+  private static final byte[] kBinaryStringEncoding = {
+    TType.STRING, // Field Type = string
+    (byte) 0x00,
+    (byte) 0x01, // Field id = 1
+    (byte) 0x00,
+    (byte) 0x00,
+    (byte) 0x00,
+    (byte) 0xFF, // string length (255!)
+    (byte) 0x48,
+    (byte) 0x65,
+    (byte) 0x6C,
+    (byte) 0x6C,
+    (byte) 0x6F,
+    (byte) 0x2C,
+    (byte) 0x20,
+    (byte) 0x57,
+    (byte) 0x6F,
+    (byte) 0x72,
+    (byte) 0x6C,
+    (byte) 0x64,
+    (byte) 0x21, // string chars: "Hello, World!"
+    (byte) 0x00, // Stop
+  };
+
+  private static final byte[] kCompactStringEncoding = {
+    (byte) 0b00011000, // field id delta (0001) + type (1000) = Binary
+    (byte) 0xFF,
+    (byte) 0x0F, // string size (varint) = 0x0FFF (4095)
+    (byte) 0x48,
+    (byte) 0x65,
+    (byte) 0x6C,
+    (byte) 0x6C,
+    (byte) 0x6F,
+    (byte) 0x2C,
+    (byte) 0x20,
+    (byte) 0x57,
+    (byte) 0x6F,
+    (byte) 0x72,
+    (byte) 0x6C,
+    (byte) 0x64,
+    (byte) 0x21, // string chars: "Hello, World!"
+    (byte) 0x00, // Stop
+  };
+
+  @Test
+  public void testStringBinary() throws Exception {
+    TMemoryInputTransport buf = new TMemoryInputTransport(kBinaryStringEncoding);
+    TProtocol iprot = new TBinaryProtocol(buf);
+    testTruncated(new MyStringStruct(), iprot);
+  }
+
+  @Test
+  public void testStringCompact() throws Exception {
+    TMemoryInputTransport buf = new TMemoryInputTransport(kCompactStringEncoding);
+    TProtocol iprot = new TCompactProtocol(buf);
+    testTruncated(new MyStringStruct(), iprot);
   }
 }
```
