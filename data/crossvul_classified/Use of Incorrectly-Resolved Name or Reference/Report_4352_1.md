# CrossVul Fix Pair: Use of Incorrectly-Resolved Name or Reference in csharp
**Pair ID:** 4352_1
**Vulnerability Class:** Use of Incorrectly-Resolved Name or Reference
**CWE:** CWE-706
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4352_1`)

## Vulnerability Information & PoC

## Description
Use of Incorrectly-Resolved Name or Reference - The product uses a name or reference to access a resource, but the name/reference resolves to a resource that is outside of the intended control sphere.

## Vulnerable Code
```csharp
Lines 1-24 of the vulnerable file.

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
using System;
using Microsoft.Git.CredentialManager.Interop.Linux;
using Microsoft.Git.CredentialManager.Interop.MacOS;
using Microsoft.Git.CredentialManager.Interop.Posix;
using Microsoft.Git.CredentialManager.Interop.Windows;

namespace Microsoft.Git.CredentialManager
{
    /// <summary>
    /// Represents the execution environment for a Git credential helper command.
    /// </summary>
    public interface ICommandContext : IDisposable
    {
        /// <summary>
        /// Settings and configuration for Git Credential Manager.
        /// </summary>
        ISettings Settings { get; }

        /// <summary>
        /// Standard I/O text streams, typically connected to the parent Git process.
        /// </summary>
        IStandardStreams Streams { get; }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,7 @@
 // Copyright (c) Microsoft Corporation. All rights reserved.
 // Licensed under the MIT license.
 using System;
+using System.IO;
 using Microsoft.Git.CredentialManager.Interop.Linux;
 using Microsoft.Git.CredentialManager.Interop.MacOS;
 using Microsoft.Git.CredentialManager.Interop.Posix;
@@ -86,9 +87,10 @@
                 SystemPrompts     = new WindowsSystemPrompts();
                 Environment       = new WindowsEnvironment(FileSystem);
                 Terminal          = new WindowsTerminal(Trace);
+                string gitPath    = GetGitPath(Environment, FileSystem);
                 Git               = new GitProcess(
                                             Trace,
-                                            Environment.LocateExecutable("git.exe"),
+                                            gitPath,
                                             FileSystem.GetCurrentDirectory()
                                         );
                 Settings          = new Settings(Environment, Git);
@@ -101,9 +103,10 @@
                 SystemPrompts     = new MacOSSystemPrompts();
                 Environment       = new PosixEnvironment(FileSystem);
                 Terminal          = new PosixTerminal(Trace);
+                string gitPath    = GetGitPath(Environment, FileSystem);
                 Git               = new GitProcess(
                                             Trace,
-                                            Environment.LocateExecutable("git"),
+                                            gitPath,
                                             FileSystem.GetCurrentDirectory()
                                         );
                 Settings          = new Settings(Environment, Git);
@@ -117,9 +120,10 @@
                 SystemPrompts     = new LinuxSystemPrompts();
                 Environment       = new PosixEnvironment(FileSystem);
                 Terminal          = new PosixTerminal(Trace);
+                string gitPath    = GetGitPath(Environment, FileSystem);
                 Git               = new GitProcess(
                                             Trace,
-                                            Environment.LocateExecutable("git"),
+                                            gitPath,
                                             FileSystem.GetCurrentDirectory()
                                         );
                 Settings          = new Settings(Environment, Git);
@@ -140,6 +144,25 @@
             SystemPrompts.ParentWindowId = Settings.ParentWindowId;
         }
 
+        private static string GetGitPath(IEnvironment environment, IFileSystem fileSystem)
+        {
+            string programName = PlatformUtils.IsWindows() ? "git.exe" : "git";
+
+            // Use the GIT_EXEC_PATH environment variable if set
+            if (environment.Variables.TryGetValue(Constants.EnvironmentVariables.GitExecutablePath,
+                out string gitExecPath))
+            {
+                string candidatePath = Path.Combine(gitExecPath, programName);
+                if (fileSystem.FileExists(candidatePath))
+                {
+                    return candidatePath;
+                }
+            }
+
+            // Otherwise try to locate the git(.exe) on the current PATH
+            return environment.LocateExecutable(programName);
+        }
+
         #region ICommandContext
 
         public ISettings Settings { get; }
```
