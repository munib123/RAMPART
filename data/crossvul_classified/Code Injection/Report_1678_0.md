# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 1678_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1678_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 2-42 of the vulnerable file.

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

import org.elasticsearch.common.Classes;

import java.io.*;

/**
 *
 */
public class ThrowableObjectInputStream extends ObjectInputStream {

    private final ClassLoader classLoader;

    public ThrowableObjectInputStream(InputStream in) throws IOException {
        this(in, null);
    }

    public ThrowableObjectInputStream(InputStream in, ClassLoader classLoader) throws IOException {
        super(in);
        this.classLoader = classLoader;
    }

    @Override
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,9 +19,15 @@
 
 package org.elasticsearch.common.io;
 
+import com.fasterxml.jackson.core.JsonLocation;
+import com.google.common.collect.ImmutableMap;
 import org.elasticsearch.common.Classes;
+import org.elasticsearch.common.collect.IdentityHashSet;
+import org.joda.time.DateTimeFieldType;
 
 import java.io.*;
+import java.net.*;
+import java.util.*;
 
 /**
  *
@@ -61,11 +67,11 @@
             case ThrowableObjectOutputStream.TYPE_STACKTRACEELEMENT:
                 return ObjectStreamClass.lookup(StackTraceElement.class);
             case ThrowableObjectOutputStream.TYPE_FAT_DESCRIPTOR:
-                return super.readClassDescriptor();
+                return verify(super.readClassDescriptor());
             case ThrowableObjectOutputStream.TYPE_THIN_DESCRIPTOR:
                 String className = readUTF();
                 Class<?> clazz = loadClass(className);
-                return ObjectStreamClass.lookup(clazz);
+                return verify(ObjectStreamClass.lookup(clazz));
             default:
                 throw new StreamCorruptedException(
                         "Unexpected class descriptor type: " + type);
@@ -96,4 +102,40 @@
         }
         return clazz;
     }
+
+    private static final Set<Class<?>> CLASS_WHITELIST;
+    private static final Set<Package> PKG_WHITELIST;
+    static {
+        IdentityHashSet<Class<?>> classes = new IdentityHashSet<>();
+        classes.add(String.class);
+        // inet stuff is needed for DiscoveryNode
+        classes.add(Inet6Address.class);
+        classes.add(Inet4Address.class);
+        classes.add(InetAddress.class);
+        classes.add(InetSocketAddress.class);
+        classes.add(SocketAddress.class);
+        classes.add(StackTraceElement.class);
+        classes.add(JsonLocation.class); // JsonParseException uses this
+        IdentityHashSet<Package> packages = new IdentityHashSet<>();
+        packages.add(Integer.class.getPackage()); // java.lang
+        packages.add(List.class.getPackage()); // java.util
+        packages.add(ImmutableMap.class.getPackage()); // com.google.common.collect
+        packages.add(DateTimeFieldType.class.getPackage()); // org.joda.time
+        CLASS_WHITELIST = Collections.unmodifiableSet(classes);
+        PKG_WHITELIST = Collections.unmodifiableSet(packages);
+    }
+
+    private ObjectStreamClass verify(ObjectStreamClass streamClass) throws IOException, ClassNotFoundException {
+        Class<?> aClass = resolveClass(streamClass);
+        Package pkg = aClass.getPackage();
+        if (aClass.isPrimitive() // primitives are fine
+                || aClass.isArray() // arrays are ok too
+                || Throwable.class.isAssignableFrom(aClass)// exceptions are fine
+                || CLASS_WHITELIST.contains(aClass) // whitelist JDK stuff we need
+                || PKG_WHITELIST.contains(aClass.getPackage())
+                || pkg.getName().startsWith("org.elasticsearch")) { // es classes are ok
+            return streamClass;
+        }
+        throw new NotSerializableException(aClass.getName());
+    }
 }
```
