# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 4612_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4612_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 1346-1386 of the vulnerable file.

    return appendDefinition(verb, path, filter);
  }

  @Override
  public Route.Definition use(final String verb, final String path, final Route.Handler handler) {
    return appendDefinition(verb, path, handler);
  }

  @Override
  public Route.Definition use(final String path, final Route.Handler handler) {
    return appendDefinition("*", path, handler);
  }

  @Override
  public Route.Definition use(final String path, final Route.OneArgHandler handler) {
    return appendDefinition("*", path, handler);
  }

  @Override
  public Route.Definition get(final String path, final Route.Handler handler) {
    return appendDefinition(GET, path, handler);
  }

  @Override
  public Route.Collection get(final String path1, final String path2, final Route.Handler handler) {
    return new Route.Collection(
        new Route.Definition[]{get(path1, handler), get(path2, handler)});
  }

  @Override
  public Route.Collection get(final String path1, final String path2, final String path3,
      final Route.Handler handler) {
    return new Route.Collection(
        new Route.Definition[]{get(path1, handler), get(path2, handler), get(path3, handler)});
  }

  @Override
  public Route.Definition get(final String path, final Route.OneArgHandler handler) {
    return appendDefinition(GET, path, handler);
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1363,7 +1363,11 @@
 
   @Override
   public Route.Definition get(final String path, final Route.Handler handler) {
-    return appendDefinition(GET, path, handler);
+    if (handler instanceof AssetHandler) {
+      return assets(path, (AssetHandler) handler);
+    } else {
+      return appendDefinition(GET, path, handler);
+    }
   }
 
   @Override
```
