# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in csharp
**Pair ID:** 5811_5
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5811_5`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```csharp
Lines 1-38 of the vulnerable file.

// Copyright 2011 OpenStack LLC.
// All Rights Reserved.
//
//    Licensed under the Apache License, Version 2.0 (the "License"); you may
//    not use this file except in compliance with the License. You may obtain
//    a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
//    License for the specific language governing permissions and limitations
//    under the License.

using System;
using System.Reflection;
using System.Timers;
using Rackspace.Cloud.Server.Agent.Interfaces;
using Rackspace.Cloud.Server.Common.Logging;
using StructureMap;
using StructureMap.Configuration.DSL;

namespace Rackspace.Cloud.Server.Agent.Service {
    public class ServerClass {
        private readonly ILogger _logger;
        private ITimer _timer;

        public ServerClass(ILogger logger) {
            _logger = logger;
        }

        public void Onstart() {
            _logger.Log("Agent Service Starting ...");
            _logger.Log("Agent Version: " + Assembly.GetExecutingAssembly().GetName().Version);

            const int TIMER_INTERVAL_IS_SIX_SECONDS = 6000;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,7 +15,9 @@
 
 using System;
 using System.Reflection;
+using System.Text;
 using System.Timers;
+using Rackspace.Cloud.Server.Agent.Commands;
 using Rackspace.Cloud.Server.Agent.Interfaces;
 using Rackspace.Cloud.Server.Common.Logging;
 using StructureMap;
@@ -38,11 +40,15 @@
 
             _timer = new ProdTimer { Interval = TIMER_INTERVAL_IS_SIX_SECONDS };
             _timer.Elapsed(TimerElapsed);
-            _timer.Enabled = true;
+            
 
             StructureMapConfiguration.UseDefaultStructureMapConfigFile = false;
             StructureMapConfiguration.BuildInstancesOf<ITimer>().TheDefaultIs(Registry.Object(_timer));
             IoC.Register();
+
+            CheckAgentUpdater();
+
+            _timer.Enabled = true;
         }
 
         public void Onstop() {
@@ -58,5 +64,31 @@
                 _logger.Log("Exception was : " + ex.Message + "\nStackTrace Was: " + ex.StackTrace);
             }
         }
+
+        private void CheckAgentUpdater()
+        {
+            try
+            {
+                var minAgentUpdater = new CommandFactory().CreateCommand(Utilities.Commands.ensureminagentupdater.ToString());
+                var result = minAgentUpdater.Execute(string.Empty);
+                if (result.ExitCode == "1")
+                {
+                    var sb = new StringBuilder();
+                    if (result.Error != null)
+                    {
+                        foreach (var error in result.Error)
+                        {
+                            sb.AppendLine(error);
+                        }
+                    }
+                    
+                    throw new Exception(sb.ToString());
+                }
+            }
+            catch (Exception ex)
+            {
+                _logger.Log(string.Format("Error checking the min version of the updater and updating: {0}", ex));
+            }
+        }
     }
 }
```
