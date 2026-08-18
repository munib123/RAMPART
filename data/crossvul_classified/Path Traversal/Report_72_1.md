# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in csharp
**Pair ID:** 72_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `72_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```csharp
Lines 416-456 of the vulnerable file.

        public void Zip_Deflate_PKWear_Multipy_Entry_Access()
        {
            string zipFile = Path.Combine(TEST_ARCHIVES_PATH, "Zip.deflate.pkware.zip");

            using (FileStream fileStream = File.Open(zipFile, FileMode.Open))
            {
                using (IArchive archive = ArchiveFactory.Open(fileStream, new ReaderOptions { Password = "12345678" }))
                {
                    var entries = archive.Entries.Where(entry => !entry.IsDirectory);
                    foreach (IArchiveEntry entry in entries)
                    {
                        for (var i = 0; i < 100; i++)
                        {
                            using (var memoryStream = new MemoryStream())
                            using (Stream entryStream = entry.OpenEntryStream())
                                entryStream.CopyTo(memoryStream);
                        }
                    }
                }
            }

        }

        class NonSeekableMemoryStream : MemoryStream
        {
            public override bool CanSeek => false;
        }

        [Fact]
        public void TestSharpCompressWithEmptyStream()
        {
            MemoryStream stream = new NonSeekableMemoryStream();

            using (IWriter zipWriter = WriterFactory.Open(stream, ArchiveType.Zip, CompressionType.Deflate))
            {
                zipWriter.Write("foo.txt", new MemoryStream(new byte[0]));
                zipWriter.Write("foo2.txt", new MemoryStream(new byte[10]));
            }

            stream = new MemoryStream(stream.ToArray());
            File.WriteAllBytes(Path.Combine(SCRATCH_FILES_PATH, "foo.zip"), stream.ToArray());
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -433,7 +433,34 @@
                     }
                 }
             }
-
+        }
+
+        [Fact]
+        public void Zip_Evil_Throws_Exception()
+        {
+            Exception expectedExcetpion = null;
+            string zipFile = Path.Combine(TEST_ARCHIVES_PATH, "Zip.Evil.zip");
+
+            try
+            { 
+                using (var archive = ZipArchive.Open(zipFile))
+                {
+                    foreach (var entry in archive.Entries.Where(entry => !entry.IsDirectory))
+                    {
+                        entry.WriteToDirectory(SCRATCH_FILES_PATH, new ExtractionOptions()
+                        {
+                            ExtractFullPath = true,
+                            Overwrite = true
+                        });
+                    }
+                }
+            }
+            catch (Exception ex)
+            {
+                expectedExcetpion = ex;
+            }
+
+            Assert.NotEqual(expectedExcetpion, null);
         }
 
         class NonSeekableMemoryStream : MemoryStream
```
