# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in csharp
**Pair ID:** 5811_9
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5811_9`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```csharp
Lines 73-104 of the vulnerable file.

            _serviceRestarter.Expect(x => x.Restart("xensvc"));
            _serviceRestarter.Expect(x => x.Restart("XenServerVssProvider"));
            _serviceRestarter.Expect(x => x.ServiceExists("XenServerVssProvider")).Return(true);
            _mockRepo.ReplayAll();
            _xentoolsUpdate.Execute(_agentUpdateInfo);
            _mockRepo.VerifyAll();
        }

        [Test]
        public void should_not_restart_vss_provider_if_service_does_not_exist()
        {
            _serviceRestarter.Expect(x => x.Restart("xensvc"));
            _serviceRestarter.Expect(x => x.Restart("XenServerVssProvider")).Repeat.Never();
            _serviceRestarter.Expect(x => x.ServiceExists("XenServerVssProvider")).Return(false);

            _mockRepo.ReplayAll();
            _xentoolsUpdate.Execute(_agentUpdateInfo);
            _mockRepo.VerifyAll();
        }

        [Test]
        public void should_throw_UnsuccessfulCommandExecutionException_if_connection_to_updater_service_fails()
        {
            _sleeper.Expect(x => x.Sleep(Arg<int>.Is.Anything));
            _connectionChecker.Stub(x => x.Check())
                .Throw(new UnsuccessfulCommandExecutionException("error message", new ExecutableResult { ExitCode = "1" }));
            var result = _xentoolsUpdate.Execute(_agentUpdateInfo);
            Assert.That(result.ExitCode, Is.EqualTo("1"));
            Assert.That(result.Error[0], Is.EqualTo("Update failed"));
        }
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -90,15 +90,15 @@
             _mockRepo.VerifyAll();
         }
 
-        [Test]
-        public void should_throw_UnsuccessfulCommandExecutionException_if_connection_to_updater_service_fails()
-        {
-            _sleeper.Expect(x => x.Sleep(Arg<int>.Is.Anything));
-            _connectionChecker.Stub(x => x.Check())
-                .Throw(new UnsuccessfulCommandExecutionException("error message", new ExecutableResult { ExitCode = "1" }));
-            var result = _xentoolsUpdate.Execute(_agentUpdateInfo);
-            Assert.That(result.ExitCode, Is.EqualTo("1"));
-            Assert.That(result.Error[0], Is.EqualTo("Update failed"));
-        }
+        //[Test]
+        //public void should_throw_UnsuccessfulCommandExecutionException_if_connection_to_updater_service_fails()
+        //{
+        //    _sleeper.Expect(x => x.Sleep(Arg<int>.Is.Anything));
+        //    _connectionChecker.Stub(x => x.Check())
+        //        .Throw(new UnsuccessfulCommandExecutionException("error message", new ExecutableResult { ExitCode = "1" }));
+        //    var result = _xentoolsUpdate.Execute(_agentUpdateInfo);
+        //    Assert.That(result.ExitCode, Is.EqualTo("1"));
+        //    Assert.That(result.Error[0], Is.EqualTo("Update failed"));
+        //}
     }
 }
```
