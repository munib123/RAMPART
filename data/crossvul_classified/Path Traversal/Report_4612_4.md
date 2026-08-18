# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 4612_4
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4612_4`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 1-24 of the vulnerable file.

package org.jooby.handlers;

import static org.easymock.EasyMock.expect;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.jooby.test.MockUnit;
import org.jooby.test.MockUnit.Block;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest({AssetHandler.class, File.class, Paths.class, Files.class })
public class AssetHandlerTest {

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,12 @@
 package org.jooby.handlers;
 
-import static org.easymock.EasyMock.expect;
-import static org.junit.Assert.assertNotNull;
+import org.jooby.Route;
+import org.jooby.test.MockUnit;
+import org.jooby.test.MockUnit.Block;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.powermock.core.classloader.annotations.PrepareForTest;
+import org.powermock.modules.junit4.PowerMockRunner;
 
 import java.io.File;
 import java.net.MalformedURLException;
@@ -11,15 +16,11 @@
 import java.nio.file.Path;
 import java.nio.file.Paths;
 
-import org.jooby.test.MockUnit;
-import org.jooby.test.MockUnit.Block;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.powermock.core.classloader.annotations.PrepareForTest;
-import org.powermock.modules.junit4.PowerMockRunner;
+import static org.easymock.EasyMock.expect;
+import static org.junit.Assert.assertNotNull;
 
 @RunWith(PowerMockRunner.class)
-@PrepareForTest({AssetHandler.class, File.class, Paths.class, Files.class })
+@PrepareForTest({AssetHandler.class, File.class, Paths.class, Files.class})
 public class AssetHandlerTest {
 
   @Test
@@ -28,24 +29,30 @@
     new MockUnit(ClassLoader.class)
         .expect(publicDir(uri, "JoobyTest.js"))
         .run(unit -> {
-          URL value = new AssetHandler("/", unit.get(ClassLoader.class))
+          URL value = newHandler(unit, "/")
               .resolve("JoobyTest.js");
           assertNotNull(value);
         });
+  }
+
+  private AssetHandler newHandler(MockUnit unit, String location) {
+    AssetHandler handler = new AssetHandler(location, unit.get(ClassLoader.class));
+    new Route.AssetDefinition("GET", "/assets/**", handler, false);
+    return handler;
   }
 
   @Test
   public void shouldCallParentOnMissing() throws Exception {
     URI uri = Paths.get("src", "test", "resources", "org", "jooby").toUri();
     new MockUnit(ClassLoader.class)
-        .expect(publicDir(uri, "index.js", false))
+        .expect(publicDir(uri, "assets/index.js", false))
         .expect(unit -> {
           ClassLoader loader = unit.get(ClassLoader.class);
-          expect(loader.getResource("index.js")).andReturn(uri.toURL());
+          expect(loader.getResource("assets/index.js")).andReturn(uri.toURL());
         })
         .run(unit -> {
-          URL value = new AssetHandler("/", unit.get(ClassLoader.class))
-              .resolve("index.js");
+          URL value = newHandler(unit, "/")
+              .resolve("assets/index.js");
           assertNotNull(value);
         });
   }
@@ -54,18 +61,18 @@
   public void ignoreMalformedURL() throws Exception {
     Path path = Paths.get("src", "test", "resources", "org", "jooby");
     new MockUnit(ClassLoader.class, URI.class)
-        .expect(publicDir(null, "index.js"))
+        .expect(publicDir(null, "assets/index.js"))
         .expect(unit -> {
           URI uri = unit.get(URI.class);
           expect(uri.toURL()).andThrow(new MalformedURLException());
         })
         .expect(unit -> {
           ClassLoader loader = unit.get(ClassLoader.class);
-          expect(loader.getResource("index.js")).andReturn(path.toUri().toURL());
+          expect(loader.getResource("assets/index.js")).andReturn(path.toUri().toURL());
         })
         .run(unit -> {
-          URL value = new AssetHandler("/", unit.get(ClassLoader.class))
-              .resolve("index.js");
+          URL value = newHandler(unit, "/")
+              .resolve("assets/index.js");
           assertNotNull(value);
         });
   }
```
