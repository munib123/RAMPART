# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 43_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `43_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 1-31 of the vulnerable file.

package org.bouncycastle.pqc.crypto.xmss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Utils for XMSS implementation.
 */
public class XMSSUtil
{

    /**
     * Calculates the logarithm base 2 for a given Integer.
     *
     * @param n Number.
     * @return Logarithm to base 2 of {@code n}.
     */
    public static int log2(int n)
    {
        int log = 0;
        while ((n >>= 1) != 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,8 @@
 import java.io.ObjectInputStream;
 import java.io.ObjectOutputStream;
 import java.io.ObjectStreamClass;
+import java.util.HashSet;
+import java.util.Set;
 
 import org.bouncycastle.crypto.Digest;
 import org.bouncycastle.util.Arrays;
@@ -382,6 +384,24 @@
     private static class CheckingStream
        extends ObjectInputStream
     {
+        private static final Set<String> components = new HashSet<>();
+
+        static
+        {
+            components.add("java.util.TreeMap");
+            components.add("java.lang.Integer");
+            components.add("java.lang.Number");
+            components.add("org.bouncycastle.pqc.crypto.xmss.BDS");
+            components.add("java.util.ArrayList");
+            components.add("org.bouncycastle.pqc.crypto.xmss.XMSSNode");
+            components.add("[B");
+            components.add("java.util.LinkedList");
+            components.add("java.util.Stack");
+            components.add("java.util.Vector");
+            components.add("[Ljava.lang.Object;");
+            components.add("org.bouncycastle.pqc.crypto.xmss.BDSTreeHash");
+        }
+
         private final Class mainClass;
         private boolean found = false;
 
@@ -409,6 +429,14 @@
                     found = true;
                 }
             }
+            else
+            {
+                if (!components.contains(desc.getName()))
+                {
+                    throw new InvalidClassException(
+                          "unexpected class: ", desc.getName());
+                }
+            }
             return super.resolveClass(desc);
         }
     }
```
