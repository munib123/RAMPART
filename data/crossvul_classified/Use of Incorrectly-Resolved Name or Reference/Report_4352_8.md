# CrossVul Fix Pair: Use of Incorrectly-Resolved Name or Reference in csharp
**Pair ID:** 4352_8
**Vulnerability Class:** Use of Incorrectly-Resolved Name or Reference
**CWE:** CWE-706
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4352_8`)

## Vulnerability Information & PoC

## Description
Use of Incorrectly-Resolved Name or Reference - The product uses a name or reference to access a resource, but the name/reference resolves to a resource that is outside of the intended control sphere.

## Vulnerable Code
```csharp
Lines 1-32 of the vulnerable file.

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace Microsoft.Git.CredentialManager.Tests.Objects
{
    public class TestEnvironment : IEnvironment
    {
        private readonly IEqualityComparer<string> _pathComparer;
        private readonly IEqualityComparer<string> _envarComparer;
        private readonly string _envPathSeparator;

        public TestEnvironment(string envPathSeparator = null, IEqualityComparer<string> pathComparer = null, IEqualityComparer<string> envarComparer = null)
        {
            // Use the current platform separators and comparison types by default
            _envPathSeparator = envPathSeparator ?? (PlatformUtils.IsWindows() ? ";" : ":");

            _envarComparer = envarComparer ??
                             (PlatformUtils.IsWindows()
                                 ? StringComparer.OrdinalIgnoreCase
                                 : StringComparer.Ordinal);

            _pathComparer = pathComparer ??
                            (PlatformUtils.IsLinux()
                                ? StringComparer.Ordinal
                                : StringComparer.OrdinalIgnoreCase);

            _envPathSeparator = envPathSeparator;
            Variables = new Dictionary<string, string>(_envarComparer);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,12 +9,15 @@
 {
     public class TestEnvironment : IEnvironment
     {
+        private readonly IFileSystem _fileSystem;
         private readonly IEqualityComparer<string> _pathComparer;
         private readonly IEqualityComparer<string> _envarComparer;
         private readonly string _envPathSeparator;
 
-        public TestEnvironment(string envPathSeparator = null, IEqualityComparer<string> pathComparer = null, IEqualityComparer<string> envarComparer = null)
+        public TestEnvironment(IFileSystem fileSystem = null, string envPathSeparator = null, IEqualityComparer<string> pathComparer = null, IEqualityComparer<string> envarComparer = null)
         {
+            _fileSystem = fileSystem ?? new TestFileSystem();
+
             // Use the current platform separators and comparison types by default
             _envPathSeparator = envPathSeparator ?? (PlatformUtils.IsWindows() ? ";" : ":");
 
@@ -28,15 +31,11 @@
                                 ? StringComparer.Ordinal
                                 : StringComparer.OrdinalIgnoreCase);
 
-            _envPathSeparator = envPathSeparator;
             Variables = new Dictionary<string, string>(_envarComparer);
-            WhichFiles = new Dictionary<string, ICollection<string>>(_pathComparer);
             Symlinks = new Dictionary<string, string>(_pathComparer);
         }
 
         public IDictionary<string, string> Variables { get; set; }
-
-        public IDictionary<string, ICollection<string>> WhichFiles { get; set; }
 
         public IDictionary<string, string> Symlinks { get; set; }
 
@@ -82,18 +81,18 @@
 
         public bool TryLocateExecutable(string program, out string path)
         {
-            if (WhichFiles.TryGetValue(program, out ICollection<string> paths))
+            if (Variables.TryGetValue("PATH", out string pathValue))
             {
-                path = paths.First();
-                return true;
-            }
-
-            if (!System.IO.Path.HasExtension(program) && PlatformUtils.IsWindows())
-            {
-                // If we're testing on a Windows platform, don't have a file extension, and were unable to locate
-                // the executable file.. try appending .exe.
-                path = WhichFiles.TryGetValue($"{program}.exe", out paths) ? paths.First() : null;
-                return !(path is null);
+                string[] paths = pathValue.Split(new[]{_envPathSeparator}, StringSplitOptions.None);
+                foreach (var basePath in paths)
+                {
+                    string candidatePath = System.IO.Path.Combine(basePath, program);
+                    if (_fileSystem.FileExists(candidatePath))
+                    {
+                        path = candidatePath;
+                        return true;
+                    }
+                }
             }
 
             path = null;
```
