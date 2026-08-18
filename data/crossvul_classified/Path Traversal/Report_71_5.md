# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in csharp
**Pair ID:** 71_5
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `71_5`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```csharp
Lines 138-178 of the vulnerable file.

        /// swapping backslashes for forward slashes.
        /// </summary>
        /// <param name="pathName">source path.</param>
        /// <returns>transformed path</returns>
        public static string NormalizePathForUseInZipFile(string pathName)
        {
            // boundary case
            if (String.IsNullOrEmpty(pathName)) return pathName;

            // trim volume if necessary
            if ((pathName.Length >= 2)  && ((pathName[1] == ':') && (pathName[2] == '\\')))
                pathName =  pathName.Substring(3);

            // swap slashes
            pathName = pathName.Replace('\\', '/');

            // trim all leading slashes
            while (pathName.StartsWith("/")) pathName = pathName.Substring(1);

            return SimplifyFwdSlashPath(pathName);
        }


        //static System.Text.Encoding ibm437 = System.Text.Encoding.GetEncoding("IBM437");
        static System.Text.Encoding utf8 = System.Text.Encoding.GetEncoding("UTF-8");

        internal static byte[] StringToByteArray(string value, System.Text.Encoding encoding)
        {
            byte[] a = encoding.GetBytes(value);
            return a;
        }
        internal static byte[] StringToByteArray(string value)
        {
            System.Text.Encoding ibm437 = null;
            try
            {
                ibm437 = System.Text.Encoding.GetEncoding("IBM437");
            }
            catch (Exception /*e*/)
            {

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -155,6 +155,46 @@
             while (pathName.StartsWith("/")) pathName = pathName.Substring(1);
 
             return SimplifyFwdSlashPath(pathName);
+        }
+
+        /// <summary>
+        /// Sanitize paths in zip files. This means making sure that relative paths in a zip file don't go outside
+        /// the top directory. Entries like something/../../../../Temp/evil.txt get sanitized to Temp/evil.txt
+        /// when extracting
+        /// </summary>
+        /// <param name="path">A path with forward slashes as directory separator</param>
+        /// <returns>sanitized path</returns>
+        public static string SanitizePath(string path)
+        {
+            System.Collections.Generic.List<string> dirs = new System.Collections.Generic.List<string>();
+            int level = 0;
+            foreach (string dir in path.Split('/'))
+            {
+                if (dir == "..")
+                {
+                    if (level == 0)
+                        continue;
+                    level--;
+                }
+                else
+                {
+                    if (dirs.Count - 1 < level)
+                        dirs.Add(dir);
+                    else
+                        dirs[level] = dir;
+                    level++;
+                }
+            }
+
+            path = "";
+            for (int i = 0; i < level; i++)
+            {
+                if (i > 0)
+                    path += "/";
+                path += dirs[i];
+            }
+
+            return path;
         }
 
 
```
