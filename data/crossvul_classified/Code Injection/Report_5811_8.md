# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in csharp
**Pair ID:** 5811_8
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5811_8`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```csharp
Lines 1-27 of the vulnerable file.

﻿using System.Collections.Generic;
using NUnit.Framework;
using NUnit.Framework.SyntaxHelpers;
using Rackspace.Cloud.Server.Agent.Actions;
using Rackspace.Cloud.Server.Agent.Commands;
using Rackspace.Cloud.Server.Agent.Configuration;
using Rackspace.Cloud.Server.Common.Logging;
using Rhino.Mocks;

namespace Rackspace.Cloud.Server.Agent.Specs
{
    [TestFixture]
    public class UpdaterUpdateSpec
    {
        private IAgentUpdateMessageHandler _agentUpdateMessageHandler;
        private IDownloader _downloader;
        private IUnzipper _unzipper;
        private ISleeper _sleeper;
        private IChecksumValidator _checksumValidator;
        private IFileCopier _fileCopier;
        private IFinalizer _finalizer;
        private UpdaterUpdate _updaterUpdate;
        private string _agentUpdateInfo;
        private IConnectionChecker _connectionChecker;
        private IServiceStopper _serviceStopper;
        private IServiceStarter _serviceStarter;
        private ILogger _logger;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,7 @@
 using Rackspace.Cloud.Server.Agent.Actions;
 using Rackspace.Cloud.Server.Agent.Commands;
 using Rackspace.Cloud.Server.Agent.Configuration;
+using Rackspace.Cloud.Server.Common.Configuration;
 using Rackspace.Cloud.Server.Common.Logging;
 using Rhino.Mocks;
 
@@ -25,6 +26,7 @@
         private IServiceStopper _serviceStopper;
         private IServiceStarter _serviceStarter;
         private ILogger _logger;
+        private IBackupUpdater _backupUpdater;
 
         [SetUp]
         public void Setup()
@@ -41,11 +43,12 @@
             _logger = MockRepository.GenerateMock<ILogger>();
             _serviceStopper = MockRepository.GenerateMock<IServiceStopper>();
             _serviceStarter = MockRepository.GenerateMock<IServiceStarter>();
+            _backupUpdater = MockRepository.GenerateMock<IBackupUpdater>();
             _agentUpdateMessageHandler = new AgentUpdateMessageHandler();
 
             _logger.Stub(x => x.Log(Arg<string>.Is.Anything));
 
-            _updaterUpdate = new UpdaterUpdate(_sleeper, _downloader, _checksumValidator, _unzipper, _fileCopier, _finalizer, _serviceStopper, _serviceStarter, _connectionChecker, _agentUpdateMessageHandler, _logger);
+            _updaterUpdate = new UpdaterUpdate(_sleeper, _downloader, _checksumValidator, _unzipper, _fileCopier, _finalizer, _serviceStopper, _serviceStarter, _connectionChecker, _agentUpdateMessageHandler, _logger, _backupUpdater);
 
         }
 
@@ -70,15 +73,29 @@
             _updaterUpdate.Execute(_agentUpdateInfo);
         }
 
-        [Test]
-        public void should_throw_UnsuccessfulCommandExecutionException_if_connection_to_updater_service_fails()
-        {
-            _sleeper.Expect(x => x.Sleep(Arg<int>.Is.Anything));
-            _connectionChecker.Stub(x => x.Check())
-                .Throw(new UnsuccessfulCommandExecutionException("error message", new ExecutableResult { ExitCode = "1" }));
-            var result = _updaterUpdate.Execute(_agentUpdateInfo);
-            Assert.That(result.ExitCode, Is.EqualTo("1"));
-            Assert.That(result.Error[0], Is.EqualTo("Update failed"));
-        }
+        //[Test]
+        //public void should_throw_UnsuccessfulCommandExecutionException_if_connection_to_updater_service_fails()
+        //{
+        //    _sleeper.Expect(x => x.Sleep(Arg<int>.Is.Anything));
+        //    _connectionChecker.Stub(x => x.Check())
+        //        .Throw(new UnsuccessfulCommandExecutionException("error message", new ExecutableResult { ExitCode = "1" }));
+        //    var result = _updaterUpdate.Execute(_agentUpdateInfo);
+        //    Assert.That(result.ExitCode, Is.EqualTo("1"));
+        //    Assert.That(result.Error[0], Is.EqualTo("Update failed"));
+        //}
+
+        //[Test]
+        //public void GetChecksum()
+        //{
+        //    ChecksumValidator val = new ChecksumValidator(_logger);
+        //    val.Validate("", @"C:\Agent Services\Single Deploy 1.2.6.0\AgentService.zip");
+        //}
+
+        //[Test]
+        //public void ExtractFile()
+        //{
+        //    new ExtractEmbededResource().Extract(@"C:\Agent Services\Testing\", Constants.UpdaterEmbeddedReleasePackagePath, Constants.UpdaterReleasePackageName);
+        //    new Unzipper(_logger).Unzip( @"C:\Agent Services\Testing\" + Constants.UpdaterReleasePackageName, @"C:\Agent Services\Testing\updater", "");
+        //}
     }
 }
```
