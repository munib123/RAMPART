# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in csharp
**Pair ID:** 72_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `72_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```csharp
Lines 31-71 of the vulnerable file.

            using (entryStream)
            {
                using (Stream s = new ListeningStream(streamListener, entryStream))
                {
                    s.TransferTo(streamToWriteTo);
                }
            }
            streamListener.FireEntryExtractionEnd(archiveEntry);
        }

#if !NO_FILE

/// <summary>
/// Extract to specific directory, retaining filename
/// </summary>
        public static void WriteToDirectory(this IArchiveEntry entry, string destinationDirectory,
                                            ExtractionOptions options = null)
        {
            string destinationFileName;
            string file = Path.GetFileName(entry.Key);

            options = options ?? new ExtractionOptions()
                                 {
                                     Overwrite = true
                                 };


            if (options.ExtractFullPath)
            {
                string folder = Path.GetDirectoryName(entry.Key);
                string destdir = Path.Combine(destinationDirectory, folder);
                if (!Directory.Exists(destdir))
                {
                    Directory.CreateDirectory(destdir);
                }
                destinationFileName = Path.Combine(destdir, file);
            }
            else
            {
                destinationFileName = Path.Combine(destinationDirectory, file);
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,6 +48,7 @@
         {
             string destinationFileName;
             string file = Path.GetFileName(entry.Key);
+            string fullDestinationDirectoryPath = Path.GetFullPath(destinationDirectory);
 
             options = options ?? new ExtractionOptions()
                                  {
@@ -58,19 +59,35 @@
             if (options.ExtractFullPath)
             {
                 string folder = Path.GetDirectoryName(entry.Key);
-                string destdir = Path.Combine(destinationDirectory, folder);
+                string destdir = Path.GetFullPath(
+                                    Path.Combine(fullDestinationDirectoryPath, folder)
+                                 );
+
                 if (!Directory.Exists(destdir))
                 {
+                    if (!destdir.StartsWith(fullDestinationDirectoryPath))
+                    {
+                        throw new ExtractionException("Entry is trying to create a directory outside of the destination directory.");
+                    }
+
                     Directory.CreateDirectory(destdir);
                 }
                 destinationFileName = Path.Combine(destdir, file);
             }
             else
             {
-                destinationFileName = Path.Combine(destinationDirectory, file);
+                destinationFileName = Path.Combine(fullDestinationDirectoryPath, file);
             }
+
             if (!entry.IsDirectory)
             {
+                destinationFileName = Path.GetFullPath(destinationFileName);
+
+                if (!destinationFileName.StartsWith(fullDestinationDirectoryPath))
+                {
+                    throw new ExtractionException("Entry is trying to write a file outside of the destination directory.");
+                }
+
                 entry.WriteToFile(destinationFileName, options);
             }
         }
```
