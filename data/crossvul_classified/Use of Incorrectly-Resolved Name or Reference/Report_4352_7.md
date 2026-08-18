# CrossVul Fix Pair: Use of Incorrectly-Resolved Name or Reference in csharp
**Pair ID:** 4352_7
**Vulnerability Class:** Use of Incorrectly-Resolved Name or Reference
**CWE:** CWE-706
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4352_7`)

## Vulnerability Information & PoC

## Description
Use of Incorrectly-Resolved Name or Reference - The product uses a name or reference to access a resource, but the name/reference resolves to a resource that is outside of the intended control sphere.

## Vulnerable Code
```csharp
Lines 3-43 of the vulnerable file.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text;

namespace Microsoft.Git.CredentialManager.Tests.Objects
{
    public class TestCommandContext : ICommandContext
    {
        public TestCommandContext()
        {
            Streams = new TestStandardStreams();
            Terminal = new TestTerminal();
            SessionManager = new TestSessionManager();
            Trace = new NullTrace();
            FileSystem = new TestFileSystem();
            CredentialStore = new TestCredentialStore();
            HttpClientFactory = new TestHttpClientFactory();
            Git = new TestGit();
            Environment = new TestEnvironment();
            SystemPrompts = new TestSystemPrompts();

            Settings = new TestSettings {Environment = Environment, GitConfiguration = Git.GlobalConfiguration};
        }

        public TestSettings Settings { get; set; }
        public TestStandardStreams Streams { get; set; }
        public TestTerminal Terminal { get; set; }
        public TestSessionManager SessionManager { get; set; }
        public ITrace Trace { get; set; }
        public TestFileSystem FileSystem { get; set; }
        public TestCredentialStore CredentialStore { get; set; }
        public TestHttpClientFactory HttpClientFactory { get; set; }
        public TestGit Git { get; set; }
        public TestEnvironment Environment { get; set; }
        public TestSystemPrompts SystemPrompts { get; set; }

        #region ICommandContext

        IStandardStreams ICommandContext.Streams => Streams;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,7 +20,7 @@
             CredentialStore = new TestCredentialStore();
             HttpClientFactory = new TestHttpClientFactory();
             Git = new TestGit();
-            Environment = new TestEnvironment();
+            Environment = new TestEnvironment(FileSystem);
             SystemPrompts = new TestSystemPrompts();
 
             Settings = new TestSettings {Environment = Environment, GitConfiguration = Git.GlobalConfiguration};
```
