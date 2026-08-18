# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in csharp
**Pair ID:** 71_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `71_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```csharp
Lines 2564-2604 of the vulnerable file.


        [TestMethod]
        public void Extract_DWF()
        {
            _Extract_ZipFile("plot.dwf");
        }

        [TestMethod]
        public void Extract_InfoZipAppNote()
        {
            _Extract_ZipFile("appnote-iz-latest.zip");
        }

        [TestMethod]
        public void Extract_AndroidApp()
        {
            _Extract_ZipFile("Calendar.apk");
        }


        private void _Extract_ZipFile(string fileName)
        {
            TestContext.WriteLine("Current Dir: {0}", CurrentDir);
            string sourceDir = CurrentDir;
            for (int i = 0; i < 3; i++)
                sourceDir = Path.GetDirectoryName(sourceDir);

            string fqFileName = Path.Combine(Path.Combine(sourceDir,
                                                             "Zip Tests\\bin\\Debug\\zips"),
                                                fileName);

            TestContext.WriteLine("Reading zip file: '{0}'", fqFileName);
            using (ZipFile zip = ZipFile.Read(fqFileName))
            {
                string extractDir = "extract";
                foreach (ZipEntry e in zip)
                {

                    TestContext.WriteLine("{1,-22} {2,9} {3,5:F0}%   {4,9}  {5,3} {6:X8} {0}",
                                                                         e.FileName,
                                                                         e.LastModified.ToString("yyyy-MM-dd HH:mm:ss"),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2581,6 +2581,30 @@
         }
 
 
+        [TestMethod]
+        public void Extract_ZipWithRelativePathsOutside()
+        {
+            _Extract_ZipFile("relative-paths-outside.zip");
+            Assert.IsTrue(File.Exists(@"extract\good.txt"));
+            Assert.IsTrue(File.Exists(@"extract\Temp\evil.txt"));
+        }
+
+        [TestMethod]
+        public void Extract_ZipWithRelativePathsInSubdir()
+        {
+            _Extract_ZipFile("relative-paths-in-subdir.zip");
+            Assert.IsTrue(File.Exists(@"extract\good.txt"));
+            Assert.IsTrue(File.Exists(@"extract\Temp\evil.txt"));
+        }
+
+        [TestMethod]
+        public void Extract_ZipWithRelativePathsInSubdirOutside()
+        {
+            _Extract_ZipFile("relative-paths-in-subdir-outside.zip");
+            Assert.IsTrue(File.Exists(@"extract\good.txt"));
+            Assert.IsTrue(File.Exists(@"extract\Temp\evil.txt"));
+        }
+
         private void _Extract_ZipFile(string fileName)
         {
             TestContext.WriteLine("Current Dir: {0}", CurrentDir);
```
