# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 68_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `68_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 1133-1173 of the vulnerable file.


  /**
   * Unpacks each ZIP entry.
   *
   * @author Rein Raudjärv
   */
  private static class Unpacker implements ZipEntryCallback {

    private final File outputDir;
    private final NameMapper mapper;

    public Unpacker(File outputDir, NameMapper mapper) {
      this.outputDir = outputDir;
      this.mapper = mapper;
    }

    public void process(InputStream in, ZipEntry zipEntry) throws IOException {
      String name = mapper.map(zipEntry.getName());
      if (name != null) {
        File file = new File(outputDir, name);
        if (zipEntry.isDirectory()) {
          FileUtils.forceMkdir(file);
        }
        else {
          FileUtils.forceMkdir(file.getParentFile());

          if (log.isDebugEnabled() && file.exists()) {
            log.debug("Overwriting file '{}'.", zipEntry.getName());
          }

          FileUtils.copy(in, file);
        }

        ZTFilePermissions permissions = ZipEntryUtil.getZTFilePermissions(zipEntry);
        if (permissions != null) {
          ZTFilePermissionsUtil.getDefaultStategy().setPermissions(file, permissions);
        }
      }
    }
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1150,6 +1150,15 @@
       String name = mapper.map(zipEntry.getName());
       if (name != null) {
         File file = new File(outputDir, name);
+
+        /* If we see the relative traversal string of ".." we need to make sure
+         * that the outputdir + name doesn't leave the outputdir. See
+         * DirectoryTraversalMaliciousTest for details.
+         */
+        if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
+          throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
+        }
+
         if (zipEntry.isDirectory()) {
           FileUtils.forceMkdir(file);
         }
@@ -1218,11 +1227,29 @@
             parentDirectory = file;
           }
           File destFile = new File(parentDirectory, dirs[dirs.length - 1]);
+
+          /* If we see the relative traversal string of ".." we need to make sure
+           * that the outputdir + name doesn't leave the outputdir. See
+           * DirectoryTraversalMaliciousTest for details.
+           */
+          if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
+            throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
+          }
+
           FileUtils.copy(in, destFile);
         }
         // it could be that there are just top level files that the unpacker is used for
         else {
           File destFile = new File(outputDir, name);
+
+          /* If we see the relative traversal string of ".." we need to make sure
+           * that the outputdir + name doesn't leave the outputdir. See
+           * DirectoryTraversalMaliciousTest for details.
+           */
+          if (name.indexOf("..") != -1 && !destFile.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
+            throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
+          }
+
           FileUtils.copy(in, destFile);
         }
       }
@@ -1258,6 +1285,15 @@
       String name = mapper.map(getUnrootedName(root, zipEntry.getName()));
       if (name != null) {
         File file = new File(outputDir, name);
+
+        /* If we see the relative traversal string of ".." we need to make sure
+         * that the outputdir + name doesn't leave the outputdir. See
+         * DirectoryTraversalMaliciousTest for details.
+         */
+        if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
+          throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
+        }
+
         if (zipEntry.isDirectory()) {
           FileUtils.forceMkdir(file);
         }
```
