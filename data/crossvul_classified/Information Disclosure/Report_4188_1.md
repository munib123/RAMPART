# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 4188_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4188_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```java
Lines 1-26 of the vulnerable file.

package org.junit.rules;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.experimental.results.PrintableResult.testResult;
import static org.junit.experimental.results.ResultMatchers.failureCountIs;
import static org.junit.experimental.results.ResultMatchers.isSuccessful;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Arrays;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class TempFolderRuleTest {
    private static File[] createdFiles = new File[20];

    public static class HasTempFolder {
        @Rule
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,21 +3,28 @@
 import static org.hamcrest.CoreMatchers.hasItem;
 import static org.hamcrest.MatcherAssert.assertThat;
 import static org.hamcrest.core.IsNot.not;
+import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
+import static org.junit.Assume.assumeTrue;
 import static org.junit.experimental.results.PrintableResult.testResult;
 import static org.junit.experimental.results.ResultMatchers.failureCountIs;
 import static org.junit.experimental.results.ResultMatchers.isSuccessful;
 
 import java.io.File;
 import java.io.IOException;
+import java.lang.reflect.Array;
+import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.util.Arrays;
+import java.util.Set;
+import java.util.SortedSet;
+import java.util.TreeSet;
 
 import org.junit.After;
+import org.junit.AssumptionViolatedException;
 import org.junit.Rule;
 import org.junit.Test;
-import org.junit.rules.TemporaryFolder;
 
 public class TempFolderRuleTest {
     private static File[] createdFiles = new File[20];
@@ -182,6 +189,34 @@
         assertFalse(folder.getRoot().exists());
     }
 
+    @Test
+    public void tempFolderIsOnlyAccessibleByOwner() throws IOException {
+        TemporaryFolder folder = new TemporaryFolder();
+        folder.create();
+
+        Set<String> expectedPermissions = new TreeSet<String>(Arrays.asList("OWNER_READ", "OWNER_WRITE", "OWNER_EXECUTE"));
+        Set<String> actualPermissions = getPosixFilePermissions(folder.getRoot());
+        assertEquals(expectedPermissions, actualPermissions);
+    }
+
+    private Set<String> getPosixFilePermissions(File root) {
+        try {
+            Class<?> pathClass = Class.forName("java.nio.file.Path");
+            Object linkOptionArray = Array.newInstance(Class.forName("java.nio.file.LinkOption"), 0);
+            Class<?> filesClass = Class.forName("java.nio.file.Files");
+            Object path = File.class.getDeclaredMethod("toPath").invoke(root);
+            Method posixFilePermissionsMethod = filesClass.getDeclaredMethod("getPosixFilePermissions", pathClass, linkOptionArray.getClass());
+            Set<?> permissions = (Set<?>) posixFilePermissionsMethod.invoke(null, path, linkOptionArray);
+            SortedSet<String> convertedPermissions = new TreeSet<String>();
+            for (Object item : permissions) {
+                convertedPermissions.add(item.toString());
+            }
+            return convertedPermissions;
+        } catch (Exception e) {
+            throw new AssumptionViolatedException("Test requires at least Java 1.7", e);
+        }
+    }
+
     public static class NameClashes {
         @Rule
         public TemporaryFolder folder = new TemporaryFolder();
```
