# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 4188_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4188_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```java
Lines 1-27 of the vulnerable file.

package org.junit.rules;

import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;

import org.junit.Rule;

/**
 * The TemporaryFolder Rule allows creation of files and folders that should
 * be deleted when the test method finishes (whether it passes or
 * fails).
 * By default no exception will be thrown in case the deletion fails.
 *
 * <p>Example of usage:
 * <pre>
 * public static class HasTempFolder {
 *  &#064;Rule
 *  public TemporaryFolder folder= new TemporaryFolder();
 *
 *  &#064;Test
 *  public void testUsingTempFolder() throws IOException {
 *      File createdFile= folder.newFile(&quot;myfile.txt&quot;);
 *      File createdFolder= folder.newFolder(&quot;subfolder&quot;);
 *      // ...
 *     }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,9 @@
 
 import java.io.File;
 import java.io.IOException;
+import java.lang.reflect.Array;
+import java.lang.reflect.InvocationTargetException;
+import java.lang.reflect.Method;
 
 import org.junit.Rule;
 
@@ -229,7 +232,45 @@
         return createTemporaryFolderIn(getRoot());
     }
 
-    private File createTemporaryFolderIn(File parentFolder) throws IOException {
+    private static File createTemporaryFolderIn(File parentFolder) throws IOException {
+        try {
+            return createTemporaryFolderWithNioApi(parentFolder);
+        } catch (ClassNotFoundException ignore) {
+            // Fallback for Java 5 and 6
+            return createTemporaryFolderWithFileApi(parentFolder);
+        } catch (InvocationTargetException e) {
+            Throwable cause = e.getCause();
+            if (cause instanceof IOException) {
+                throw (IOException) cause;
+            }
+            if (cause instanceof RuntimeException) {
+                throw (RuntimeException) cause;
+            }
+            IOException exception = new IOException("Failed to create temporary folder in " + parentFolder);
+            exception.initCause(cause);
+            throw exception;
+        } catch (Exception e) {
+            throw new RuntimeException("Failed to create temporary folder in " + parentFolder, e);
+        }
+    }
+
+    private static File createTemporaryFolderWithNioApi(File parentFolder) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
+        Class<?> filesClass = Class.forName("java.nio.file.Files");
+        Object fileAttributeArray = Array.newInstance(Class.forName("java.nio.file.attribute.FileAttribute"), 0);
+        Class<?> pathClass = Class.forName("java.nio.file.Path");
+        Object tempDir;
+        if (parentFolder != null) {
+            Method createTempDirectoryMethod = filesClass.getDeclaredMethod("createTempDirectory", pathClass, String.class, fileAttributeArray.getClass());
+            Object parentPath = File.class.getDeclaredMethod("toPath").invoke(parentFolder);
+            tempDir = createTempDirectoryMethod.invoke(null, parentPath, TMP_PREFIX, fileAttributeArray);
+        } else {
+            Method createTempDirectoryMethod = filesClass.getDeclaredMethod("createTempDirectory", String.class, fileAttributeArray.getClass());
+            tempDir = createTempDirectoryMethod.invoke(null, TMP_PREFIX, fileAttributeArray);
+        }
+        return (File) pathClass.getDeclaredMethod("toFile").invoke(tempDir);
+    }
+
+    private static File createTemporaryFolderWithFileApi(File parentFolder) throws IOException {
         File createdFolder = null;
         for (int i = 0; i < TEMP_DIR_ATTEMPTS; ++i) {
             // Use createTempFile to get a suitable folder name.
```
