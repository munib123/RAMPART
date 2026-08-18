# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 4471_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4471_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 97-137 of the vulnerable file.

         // can make sense of anything we have extracted from the zip file so far.
         // For what it's worth I haven't come across a valid compressed schedule file
         // which includes zero bytes files.
         if (!ex.getMessage().equals("only DEFLATED entries can have EXT descriptor"))
         {
            throw ex;
         }
      }

      return dir;
   }

   /**
    * Expands a zip file input stream into a temporary directory.
    *
    * @param dir temporary directory
    * @param inputStream zip file input stream
    */
   private static void processZipStream(File dir, InputStream inputStream) throws IOException
   {
      ZipInputStream zip = new ZipInputStream(inputStream);
      while (true)
      {
         ZipEntry entry = zip.getNextEntry();
         if (entry == null)
         {
            break;
         }

         File file = new File(dir, entry.getName());
         if (entry.isDirectory())
         {
            FileHelper.mkdirsQuietly(file);
            continue;
         }

         File parent = file.getParentFile();
         if (parent != null)
         {
            FileHelper.mkdirsQuietly(parent);
         }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -114,6 +114,7 @@
     */
    private static void processZipStream(File dir, InputStream inputStream) throws IOException
    {
+      String canonicalDestinationDirPath = dir.getCanonicalPath();
       ZipInputStream zip = new ZipInputStream(inputStream);
       while (true)
       {
@@ -124,6 +125,14 @@
          }
 
          File file = new File(dir, entry.getName());
+
+         // https://snyk.io/research/zip-slip-vulnerability
+         String canonicalDestinationFile = file.getCanonicalPath();
+         if (!canonicalDestinationFile.startsWith(canonicalDestinationDirPath + File.separator))
+         {
+            throw new IOException("Entry is outside of the target dir: " + entry.getName());
+         }
+
          if (entry.isDirectory())
          {
             FileHelper.mkdirsQuietly(file);
```
