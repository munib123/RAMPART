# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 689_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `689_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 1-36 of the vulnerable file.

/*
 * Copyright 2011- Per Wendel
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package spark.examples.staticresources;

import static spark.Spark.get;
import static spark.Spark.staticFileLocation;

/**
 * Example showing how serve static resources.
 */
public class StaticResources {

    public static void main(String[] args) {

        // Will serve all static file are under "/public" in classpath if the route isn't consumed by others routes.
        staticFileLocation("/public");

        get("/hello", (request, response) -> {
            return "Hello World!";
        });
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,7 +17,7 @@
 package spark.examples.staticresources;
 
 import static spark.Spark.get;
-import static spark.Spark.staticFileLocation;
+import static spark.Spark.staticFiles;
 
 /**
  * Example showing how serve static resources.
@@ -27,7 +27,7 @@
     public static void main(String[] args) {
 
         // Will serve all static file are under "/public" in classpath if the route isn't consumed by others routes.
-        staticFileLocation("/public");
+        staticFiles.location("/public");
 
         get("/hello", (request, response) -> {
             return "Hello World!";
```
