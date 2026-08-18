# CrossVul Fix Pair: Creation of Temporary File in Directory with Insecure Permissions in java
**Pair ID:** 1927_8
**Vulnerability Class:** Creation of Temporary File in Directory with Insecure Permissions
**CWE:** CWE-379
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1927_8`)

## Vulnerability Information & PoC

## Description
Creation of Temporary File in Directory with Insecure Permissions - On some operating systems, the fact that the temporary file exists may be apparent to any user with sufficient privileges to access that directory.

## Vulnerable Code
```java
Lines 21-61 of the vulnerable file.

import org.jctools.queues.MpscArrayQueue;
import org.jctools.queues.MpscChunkedArrayQueue;
import org.jctools.queues.MpscUnboundedArrayQueue;
import org.jctools.queues.SpscLinkedQueue;
import org.jctools.queues.atomic.MpscAtomicArrayQueue;
import org.jctools.queues.atomic.MpscChunkedAtomicArrayQueue;
import org.jctools.queues.atomic.MpscUnboundedAtomicArrayQueue;
import org.jctools.queues.atomic.SpscLinkedAtomicQueue;
import org.jctools.util.Pow2;
import org.jctools.util.UnsafeAccess;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Queue;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,6 +38,7 @@
 import java.lang.reflect.Method;
 import java.nio.ByteBuffer;
 import java.nio.ByteOrder;
+import java.nio.file.Files;
 import java.security.AccessController;
 import java.security.PrivilegedAction;
 import java.util.Arrays;
@@ -1389,6 +1390,24 @@
         return LINUX_OS_CLASSIFIERS;
     }
 
+    @SuppressJava6Requirement(reason = "Guarded by version check")
+    public static File createTempFile(String prefix, String suffix, File directory) throws IOException {
+        if (javaVersion() >= 7) {
+            if (directory == null) {
+                return Files.createTempFile(prefix, suffix).toFile();
+            }
+            return Files.createTempFile(directory.toPath(), prefix, suffix).toFile();
+        }
+        if (directory == null) {
+            return File.createTempFile(prefix, suffix);
+        }
+        File file = File.createTempFile(prefix, suffix, directory);
+        // Try to adjust the perms, if this fails there is not much else we can do...
+        file.setReadable(false, false);
+        file.setReadable(true, true);
+        return file;
+    }
+
     /**
      * Adds only those classifier strings to <tt>dest</tt> which are present in <tt>allowed</tt>.
      *
```
