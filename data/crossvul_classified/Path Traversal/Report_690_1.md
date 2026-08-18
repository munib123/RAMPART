# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 690_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `690_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 57-97 of the vulnerable file.

     * @param path the absolute path within the class path
     * @see java.lang.ClassLoader#getResourceAsStream(String)
     * @see spark.utils.ClassUtils#getDefaultClassLoader()
     */
    public ClassPathResource(String path) {
        this(path, null);
    }

    /**
     * Create a new ClassPathResource for ClassLoader usage.
     * A leading slash will be removed, as the ClassLoader
     * resource access methods will not accept it.
     *
     * @param path        the absolute path within the classpath
     * @param classLoader the class loader to load the resource with,
     *                    or {@code null} for the thread context class loader
     * @see ClassLoader#getResourceAsStream(String)
     */
    public ClassPathResource(String path, ClassLoader classLoader) {
        Assert.notNull(path, "Path must not be null");
        String pathToUse = StringUtils.cleanPath(path);
        if (pathToUse.startsWith("/")) {
            pathToUse = pathToUse.substring(1);
        }
        this.path = pathToUse;
        this.classLoader = (classLoader != null ? classLoader : ClassUtils.getDefaultClassLoader());
    }

    /**
     * Create a new ClassPathResource with optional ClassLoader and Class.
     * Only for internal usage.
     *
     * @param path        relative or absolute path within the classpath
     * @param classLoader the class loader to load the resource with, if any
     * @param clazz       the class to load resources with, if any
     */
    protected ClassPathResource(String path, ClassLoader classLoader, Class<?> clazz) {
        this.path = StringUtils.cleanPath(path);
        this.classLoader = classLoader;
        this.clazz = clazz;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,12 +74,20 @@
      */
     public ClassPathResource(String path, ClassLoader classLoader) {
         Assert.notNull(path, "Path must not be null");
+        Assert.state(doesNotContainFileColon(path), "Path must not contain 'file:'");
+
         String pathToUse = StringUtils.cleanPath(path);
+
         if (pathToUse.startsWith("/")) {
             pathToUse = pathToUse.substring(1);
         }
+
         this.path = pathToUse;
         this.classLoader = (classLoader != null ? classLoader : ClassUtils.getDefaultClassLoader());
+    }
+
+    private static boolean doesNotContainFileColon(String path) {
+        return !path.contains("file:");
     }
 
     /**
@@ -108,10 +116,9 @@
     /**
      * This implementation checks for the resolution of a resource URL.
      *
+     * @return if exists.
      * @see java.lang.ClassLoader#getResource(String)
      * @see java.lang.Class#getResource(String)
-     *
-     * @return if exists.
      */
     @Override
     public boolean exists() {
@@ -127,10 +134,9 @@
     /**
      * This implementation opens an InputStream for the given class path resource.
      *
+     * @return the input stream.
      * @see java.lang.ClassLoader#getResourceAsStream(String)
      * @see java.lang.Class#getResourceAsStream(String)
-     *
-     * @return the input stream.
      */
     @Override
     public InputStream getInputStream() throws IOException {
@@ -149,10 +155,9 @@
     /**
      * This implementation returns a URL for the underlying class path resource.
      *
+     * @return the url.
      * @see java.lang.ClassLoader#getResource(String)
      * @see java.lang.Class#getResource(String)
-     *
-     * @return the url.
      */
     @Override
     public URL getURL() throws IOException {
@@ -172,9 +177,8 @@
      * This implementation creates a ClassPathResource, applying the given path
      * relative to the path of the underlying resource of this descriptor.
      *
+     * @return the resource.
      * @see spark.utils.StringUtils#applyRelativePath(String, String)
-     *
-     * @return the resource.
      */
     @Override
     public Resource createRelative(String relativePath) {
@@ -186,9 +190,8 @@
      * This implementation returns the name of the file that this class path
      * resource refers to.
      *
+     * @return the file name.
      * @see spark.utils.StringUtils#getFilename(String)
-     *
-     * @return the file name.
      */
     @Override
     public String getFilename() {
@@ -233,8 +236,8 @@
             ClassLoader otherLoader = otherRes.classLoader;
 
             return (this.path.equals(otherRes.path) &&
-                    thisLoader.equals(otherLoader) &&
-                    this.clazz.equals(otherRes.clazz));
+                thisLoader.equals(otherLoader) &&
+                this.clazz.equals(otherRes.clazz));
         }
         return false;
     }
```
