# CrossVul Fix Pair: Use of Incorrectly-Resolved Name or Reference in csharp
**Pair ID:** 4352_6
**Vulnerability Class:** Use of Incorrectly-Resolved Name or Reference
**CWE:** CWE-706
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4352_6`)

## Vulnerability Information & PoC

## Description
Use of Incorrectly-Resolved Name or Reference - The product uses a name or reference to access a resource, but the name/reference resolves to a resource that is outside of the intended control sphere.

## Vulnerable Code
```csharp
Lines 1-34 of the vulnerable file.

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace Microsoft.Git.CredentialManager.Interop.Windows
{
    public class WindowsEnvironment : EnvironmentBase
    {
        public WindowsEnvironment(IFileSystem fileSystem) : base(fileSystem)
        {
            Variables = GetCurrentVariables();
        }

        #region EnvironmentBase

        protected override string[] SplitPathVariable(string value)
        {
            return value.Split(';');
        }

        public override void AddDirectoryToPath(string directoryPath, EnvironmentVariableTarget target)
        {
            // Read the current PATH variable, not the cached one
            string currentValue = Environment.GetEnvironmentVariable("PATH", target) ?? string.Empty;

            // Append directory to the end
            var sb = new StringBuilder();
            sb.Append(currentValue);
            if (!currentValue.EndsWith(";"))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,9 +11,14 @@
 {
     public class WindowsEnvironment : EnvironmentBase
     {
-        public WindowsEnvironment(IFileSystem fileSystem) : base(fileSystem)
+        public WindowsEnvironment(IFileSystem fileSystem)
+            : this(fileSystem, GetCurrentVariables()) { }
+
+        internal WindowsEnvironment(IFileSystem fileSystem, IReadOnlyDictionary<string, string> variables)
+            : base(fileSystem)
         {
-            Variables = GetCurrentVariables();
+            EnsureArgument.NotNull(variables, nameof(variables));
+            Variables = variables;
         }
 
         #region EnvironmentBase
@@ -67,34 +72,24 @@
 
         public override bool TryLocateExecutable(string program, out string path)
         {
-            string wherePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "where.exe");
-            var psi = new ProcessStartInfo(wherePath, program)
+            // Don't use "where.exe" on Windows as this includes the current working directory
+            // and we don't want to enumerate this location; only the PATH.
+            if (Variables.TryGetValue("PATH", out string pathValue))
             {
-                UseShellExecute = false,
-                RedirectStandardOutput = true
-            };
-
-            using (var where = new Process {StartInfo = psi})
-            {
-                where.Start();
-                where.WaitForExit();
-
-                switch (where.ExitCode)
+                string[] paths = SplitPathVariable(pathValue);
+                foreach (var basePath in paths)
                 {
-                    case 0: // found
-                        string stdout = where.StandardOutput.ReadToEnd();
-                        string[] results = stdout.Split(new[] {'\r', '\n'}, StringSplitOptions.RemoveEmptyEntries);
-                        path = results.First();
+                    string candidatePath = Path.Combine(basePath, program);
+                    if (FileSystem.FileExists(candidatePath))
+                    {
+                        path = candidatePath;
                         return true;
-
-                    case 1: // not found
-                        path = null;
-                        return false;
-
-                    default:
-                        throw new Exception($"Unknown error locating '{program}' using where.exe. Exit code: {where.ExitCode}.");
+                    }
                 }
             }
+
+            path = null;
+            return false;
         }
 
         #endregion
```
