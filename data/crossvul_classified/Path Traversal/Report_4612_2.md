# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 4612_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4612_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 189-229 of the vulnerable file.

 *
 *    Copyright 2014 Edgar Espina
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
package org.jooby.handlers;

import com.google.common.base.Strings;
import com.typesafe.config.ConfigFactory;
import com.typesafe.config.ConfigValueFactory;
import static java.util.Objects.requireNonNull;
import org.jooby.Asset;
import org.jooby.Err;
import org.jooby.Jooby;
import org.jooby.MediaType;
import org.jooby.Request;
import org.jooby.Response;
import org.jooby.Route;
import org.jooby.Status;
import org.jooby.funzy.Throwing;
import org.jooby.funzy.Try;
import org.jooby.internal.URLAsset;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.time.Duration;
import java.util.Date;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -206,7 +206,6 @@
 import com.google.common.base.Strings;
 import com.typesafe.config.ConfigFactory;
 import com.typesafe.config.ConfigValueFactory;
-import static java.util.Objects.requireNonNull;
 import org.jooby.Asset;
 import org.jooby.Err;
 import org.jooby.Jooby;
@@ -229,6 +228,8 @@
 import java.util.Date;
 import java.util.Map;
 
+import static java.util.Objects.requireNonNull;
+
 /**
  * Serve static resources, via {@link Jooby#assets(String)} or variants.
  *
@@ -287,6 +288,12 @@
 
   private int statusCode = 404;
 
+  private String location;
+
+  private Path basedir;
+
+  private ClassLoader classLoader;
+
   /**
    * <p>
    * Creates a new {@link AssetHandler}. The handler accepts a location pattern, that serve for
@@ -315,7 +322,9 @@
    * @param loader The one who load the static resources.
    */
   public AssetHandler(final String pattern, final ClassLoader loader) {
-    init(Route.normalize(pattern), Paths.get("public"), loader);
+    this.location = Route.normalize(pattern);
+    this.basedir = Paths.get("public");
+    this.classLoader = loader;
   }
 
   /**
@@ -345,7 +354,9 @@
    * @param basedir Base directory.
    */
   public AssetHandler(final Path basedir) {
-    init("/{0}", basedir, getClass().getClassLoader());
+    this.location = "/{0}";
+    this.basedir = basedir;
+    this.classLoader = getClass().getClassLoader();
   }
 
   /**
@@ -375,7 +386,9 @@
    * @param pattern Pattern to locate static resources.
    */
   public AssetHandler(final String pattern) {
-    init(Route.normalize(pattern), Paths.get("public"), getClass().getClassLoader());
+    this.location = Route.normalize(pattern);
+    this.basedir = Paths.get("public");
+    this.classLoader = getClass().getClassLoader();
   }
 
   /**
@@ -419,6 +432,45 @@
    */
   public AssetHandler maxAge(final long maxAge) {
     this.maxAge = maxAge;
+    return this;
+  }
+
+  /**
+   * Set the route definition and initialize the handler.
+   *
+   * @param route Route definition.
+   * @return This handler.
+   */
+  public AssetHandler setRoute(final Route.AssetDefinition route) {
+    String prefix;
+    boolean rootLocation = location.equals("/") || location.equals("/{0}");
+    if (rootLocation) {
+      String pattern = route.pattern();
+      int i = pattern.indexOf("/*");
+      if (i > 0) {
+        prefix = pattern.substring(0, i + 1);
+      } else {
+        prefix = pattern;
+      }
+    } else {
+      int i = location.indexOf("{");
+      if (i > 0) {
+        prefix = location.substring(0, i);
+      } else {
+        /// TODO: review what we have here
+        prefix = location;
+      }
+    }
+    if (prefix.startsWith("/")) {
+      prefix = prefix.substring(1);
+    }
+    if (prefix.isEmpty() && rootLocation) {
+      throw new IllegalArgumentException(
+          "For security reasons root classpath access is not allowed. Map your static resources "
+              + "using a prefix like: assets(static/**); or use a location classpath prefix like: "
+              + "assets(/, /static/{0})");
+    }
+    init(prefix, location, basedir, classLoader);
     return this;
   }
 
@@ -485,7 +537,6 @@
   }
 
   private void doHandle(final Request req, final Response rsp, final Asset asset) throws Throwable {
-
     // handle etag
     if (this.etag) {
       String etag = asset.etag();
@@ -551,12 +602,13 @@
     return loader.getResource(path);
   }
 
-  private void init(final String pattern, final Path basedir, final ClassLoader loader) {
+  private void init(final String classPathPrefix, final String location, final Path basedir,
+      final ClassLoader loader) {
     requireNonNull(loader, "Resource loader is required.");
-    this.fn = pattern.equals("/")
+    this.fn = location.equals("/")
         ? (req, p) -> prefix.apply(p)
-        : (req, p) -> MessageFormat.format(prefix.apply(pattern), vars(req));
-    this.loader = loader(basedir, loader);
+        : (req, p) -> MessageFormat.format(prefix.apply(location), vars(req));
+    this.loader = loader(basedir, classpathLoader(classPathPrefix, classLoader));
   }
 
   private static Object[] vars(final Request req) {
@@ -564,8 +616,8 @@
     return vars.values().toArray(new Object[vars.size()]);
   }
 
-  private static Loader loader(final Path basedir, final ClassLoader classloader) {
-    if (Files.exists(basedir)) {
+  private static Loader loader(final Path basedir, Loader classpath) {
+    if (basedir != null && Files.exists(basedir)) {
       return name -> {
         Path path = basedir.resolve(name).normalize();
         if (Files.exists(path) && path.startsWith(basedir)) {
@@ -575,10 +627,45 @@
             // shh
           }
         }
-        return classloader.getResource(name);
+        return classpath.getResource(name);
       };
     }
-    return classloader::getResource;
+    return classpath;
+  }
+
+  private static Loader classpathLoader(String prefix, ClassLoader classloader) {
+    return name -> {
+      String safePath = safePath(name);
+      if (safePath.startsWith(prefix)) {
+        URL resource = classloader.getResource(safePath);
+        return resource;
+      }
+      return null;
+    };
+  }
+
+  private static String safePath(String name) {
+    if (name.indexOf("./") > 0) {
+      Path path = toPath(name.split("/")).normalize();
+      return toStringPath(path);
+    }
+    return name;
+  }
+
+  private static String toStringPath(Path path) {
+    StringBuilder buffer = new StringBuilder();
+    for (Path segment : path) {
+      buffer.append("/").append(segment);
+    }
+    return buffer.substring(1);
+  }
+
+  private static Path toPath(String[] segments) {
+    Path path = Paths.get(segments[0]);
+    for (int i = 1; i < segments.length; i++) {
+      path = path.resolve(segments[i]);
+    }
+    return path;
   }
 
   private static Throwing.Function<String, String> prefix() {
```
