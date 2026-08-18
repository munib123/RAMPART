# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in java
**Pair ID:** 5634_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5634_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```java
Lines 1-35 of the vulnerable file.

/*******************************************************************************
 * Copyright (C) 2009-2011 FuseSource Corp.
 * Copyright (c) 2000, 2009 IBM Corporation and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/
package org.fusesource.hawtjni.runtime;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.regex.Pattern;

/**
 * Used to optionally extract and load a JNI library.
 * 
 * It will search for the library in order at the following locations:
 * <ol>
 * <li> in the custom library path: If the "library.${name}.path" System property is set to a directory 
 *   <ol>
 *   <li> "${name}-${version}" if the version can be determined.
 *   <li> "${name}"
 *   </ol>
 * <li> system library path: This is where the JVM looks for JNI libraries by default.
 *   <ol>
 *   <li> "${name}-${version}" if the version can be determined.
 *   <li> "${name}"
 *   </ol>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,13 +9,11 @@
  *******************************************************************************/
 package org.fusesource.hawtjni.runtime;
 
-import java.io.File;
-import java.io.FileOutputStream;
-import java.io.IOException;
-import java.io.InputStream;
+import java.io.*;
 import java.net.MalformedURLException;
 import java.net.URL;
 import java.util.ArrayList;
+import java.util.Random;
 import java.util.regex.Pattern;
 
 /**
@@ -206,16 +204,19 @@
     private boolean exractAndLoad(ArrayList<String> errors, String version, String customPath, String resourcePath) {
         URL resource = classLoader.getResource(resourcePath);
         if( resource !=null ) {
-            
+
             String libName = name + "-" + getBitModel();
             if( version !=null) {
                 libName += "-" + version;
             }
-            
+            String []libNameParts = map(libName).split("\\.");
+            String prefix = libNameParts[0]+"-";
+            String suffix = "."+libNameParts[1];
+
             if( customPath!=null ) {
                 // Try to extract it to the custom path...
-                File target = file(customPath, map(libName));
-                if( extract(errors, resource, target) ) {
+                File target = extract(errors, resource, prefix, suffix, file(customPath));
+                if( target!=null ) {
                     if( load(errors, target) ) {
                         return true;
                     }
@@ -224,8 +225,8 @@
             
             // Fall back to extracting to the tmp dir
             customPath = System.getProperty("java.io.tmpdir");
-            File target = file(customPath, map(libName));
-            if( extract(errors, resource, target) ) {
+            File target = extract(errors, resource, prefix, suffix, file(customPath));
+            if( target!=null ) {
                 if( load(errors, target) ) {
                     return true;
                 }
@@ -259,67 +260,45 @@
         return libName;
     }
 
-    private boolean extract(ArrayList<String> errors, URL source, File target) {
-        FileOutputStream os = null;
-        InputStream is = null;
-        boolean extracting = false;
-        try {
-            if (!target.exists() || isStale(source, target) ) {
+    private File extract(ArrayList<String> errors, URL source, String prefix, String suffix, File directory) {
+        File target = null;
+        try {
+            FileOutputStream os = null;
+            InputStream is = null;
+            try {
+                target = File.createTempFile(prefix, suffix, directory);
                 is = source.openStream();
                 if (is != null) {
                     byte[] buffer = new byte[4096];
                     os = new FileOutputStream(target);
-                    extracting = true;
                     int read;
                     while ((read = is.read(buffer)) != -1) {
                         os.write(buffer, 0, read);
                     }
-                    os.close();
-                    is.close();
                     chmod("755", target);
                 }
+                target.deleteOnExit();
+                return target;
+            } finally {
+                close(os);
+                close(is);
             }
         } catch (Throwable e) {
+            if( target!=null ) {
+                target.delete();
+            }
+            errors.add(e.getMessage());
+        }
+        return null;
+    }
+
+    static private void close(Closeable file) {
+        if(file!=null) {
             try {
-                if (os != null)
-                    os.close();
-            } catch (IOException e1) {
-            }
-            try {
-                if (is != null)
-                    is.close();
-            } catch (IOException e1) {
-            }
-            if (extracting && target.exists())
-                target.delete();
-            errors.add(e.getMessage());
-            return false;
-        }
-        return true;
-    }
-
-    private boolean isStale(URL source, File target) {
-        
-        if( source.getProtocol().equals("jar") ) {
-            // unwrap the jar protocol...
-            try {
-                String parts[] = source.getFile().split(Pattern.quote("!"));
-                source = new URL(parts[0]);
-            } catch (MalformedURLException e) {
-                return false;
-            }
-        }
-        
-        File sourceFile=null;
-        if( source.getProtocol().equals("file") ) {
-            sourceFile = new File(source.getFile());
-        }
-        if( sourceFile!=null && sourceFile.exists() ) {
-            if( sourceFile.lastModified() > target.lastModified() ) {
-                return true;
-            }
-        }
-        return false;
+                file.close();
+            } catch (Exception ignore) {
+            }
+        }
     }
 
     private void chmod(String permision, File path) {
```
