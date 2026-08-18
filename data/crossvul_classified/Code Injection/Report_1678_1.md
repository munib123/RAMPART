# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 1678_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1678_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 2-45 of the vulnerable file.

 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.common.io;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.OutputStream;

/**
 *
 */
public class ThrowableObjectOutputStream extends ObjectOutputStream {

    static final int TYPE_FAT_DESCRIPTOR = 0;
    static final int TYPE_THIN_DESCRIPTOR = 1;

    private static final String EXCEPTION_CLASSNAME = Exception.class.getName();
    static final int TYPE_EXCEPTION = 2;

    private static final String STACKTRACEELEMENT_CLASSNAME = StackTraceElement.class.getName();
    static final int TYPE_STACKTRACEELEMENT = 3;


    public ThrowableObjectOutputStream(OutputStream out) throws IOException {
        super(out);
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,10 +19,7 @@
 
 package org.elasticsearch.common.io;
 
-import java.io.IOException;
-import java.io.ObjectOutputStream;
-import java.io.ObjectStreamClass;
-import java.io.OutputStream;
+import java.io.*;
 
 /**
  *
@@ -65,4 +62,30 @@
             }
         }
     }
+
+    /**
+     * Simple helper method to roundtrip a serializable object within the ThrowableObjectInput/Output stream
+     */
+    public static <T extends Serializable> T serialize(T t) throws IOException, ClassNotFoundException {
+        ByteArrayOutputStream stream = new ByteArrayOutputStream();
+        try (ThrowableObjectOutputStream outputStream = new ThrowableObjectOutputStream(stream)) {
+            outputStream.writeObject(t);
+        }
+        try (ThrowableObjectInputStream in = new ThrowableObjectInputStream(new ByteArrayInputStream(stream.toByteArray()))) {
+            return (T) in.readObject();
+        }
+    }
+
+    /**
+     * Returns <code>true</code> iff the exception can be serialized and deserialized using
+     * {@link ThrowableObjectOutputStream} and {@link ThrowableObjectInputStream}. Otherwise <code>false</code>
+     */
+    public static boolean canSerialize(Throwable t) {
+        try {
+            serialize(t);
+            return true;
+        } catch (Throwable throwable) {
+            return false;
+        }
+    }
 }
```
