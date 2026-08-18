# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in java
**Pair ID:** 4667_1
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4667_1`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```java
Lines 381-421 of the vulnerable file.

     * directly.
     */
    long len1 = file1.length();
    long len2 = file2.length();
    if (len1 != 0 && len2 != 0 && len1 != len2) {
      return false;
    }
    return asByteSource(file1).contentEquals(asByteSource(file2));
  }

  /**
   * Atomically creates a new directory somewhere beneath the system's temporary directory (as
   * defined by the {@code java.io.tmpdir} system property), and returns its name.
   *
   * <p>Use this method instead of {@link File#createTempFile(String, String)} when you wish to
   * create a directory, not a regular file. A common pitfall is to call {@code createTempFile},
   * delete the file and create a directory in its place, but this leads a race condition which can
   * be exploited to create security vulnerabilities, especially when executable files are to be
   * written into the directory.
   *
   * <p>This method assumes that the temporary volume is writable, has free inodes and free blocks,
   * and that it will not be called thousands of times per second.
   *
   * <p><b>{@link java.nio.file.Path} equivalent:</b> {@link
   * java.nio.file.Files#createTempDirectory}.
   *
   * @return the newly-created directory
   * @throws IllegalStateException if the directory could not be created
   */
  @Beta
  public static File createTempDir() {
    File baseDir = new File(System.getProperty("java.io.tmpdir"));
    @SuppressWarnings("GoodTime") // reading system time without TimeSource
    String baseName = System.currentTimeMillis() + "-";

    for (int counter = 0; counter < TEMP_DIR_ATTEMPTS; counter++) {
      File tempDir = new File(baseDir, baseName + counter);
      if (tempDir.mkdir()) {
        return tempDir;
      }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -398,6 +398,11 @@
    * be exploited to create security vulnerabilities, especially when executable files are to be
    * written into the directory.
    *
+   * <p>Depending on the environmment that this code is run in, the system temporary directory (and
+   * thus the directory this method creates) may be more visible that a program would like - files
+   * written to this directory may be read or overwritten by hostile programs running on the same
+   * machine.
+   *
    * <p>This method assumes that the temporary volume is writable, has free inodes and free blocks,
    * and that it will not be called thousands of times per second.
    *
@@ -406,8 +411,15 @@
    *
    * @return the newly-created directory
    * @throws IllegalStateException if the directory could not be created
-   */
-  @Beta
+   * @deprecated For Android users, see the <a
+   *     href="https://developer.android.com/training/data-storage" target="_blank">Data and File
+   *     Storage overview</a> to select an appropriate temporary directory (perhaps {@code
+   *     context.getCacheDir()}). For developers on Java 7 or later, use {@link
+   *     java.nio.file.Files#createTempDirectory}, transforming it to a {@link File} using {@link
+   *     java.nio.file.Path#toFile() toFile()} if needed.
+   */
+  @Beta
+  @Deprecated
   public static File createTempDir() {
     File baseDir = new File(System.getProperty("java.io.tmpdir"));
     @SuppressWarnings("GoodTime") // reading system time without TimeSource
```
