# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 4612_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4612_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 1619-1659 of the vulnerable file.


    private String cdn;

    private Object maxAge;

    private Boolean lastModifiedSince;

    private Integer statusCode;

    /**
     * Creates a new route definition.
     *
     * @param method A HTTP verb or <code>*</code>.
     * @param pattern A path pattern.
     * @param handler A callback to execute.
     * @param caseSensitiveRouting Configure case for routing algorithm.
     */
    public AssetDefinition(final String method, final String pattern,
        final Route.Filter handler, boolean caseSensitiveRouting) {
      super(method, pattern, handler, caseSensitiveRouting);
    }

    @Nonnull
    @Override
    public AssetHandler filter() {
      return (AssetHandler) super.filter();
    }

    /**
     * Indicates what to do when an asset is missing (not resolved). Default action is to resolve them
     * as <code>404 (NOT FOUND)</code> request.
     *
     * If you specify a status code &lt;= 0, missing assets are ignored and the next handler on pipeline
     * will be executed.
     *
     * @param statusCode HTTP code or 0.
     * @return This route definition.
     */
    public AssetDefinition onMissing(final int statusCode) {
      if (this.statusCode == null) {
        filter().onMissing(statusCode);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1636,6 +1636,7 @@
     public AssetDefinition(final String method, final String pattern,
         final Route.Filter handler, boolean caseSensitiveRouting) {
       super(method, pattern, handler, caseSensitiveRouting);
+      filter().setRoute(this);
     }
 
     @Nonnull
```
