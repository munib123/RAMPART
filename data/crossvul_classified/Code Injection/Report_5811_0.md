# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in ruby
**Pair ID:** 5811_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5811_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```ruby
Lines 1-20 of the vulnerable file.

ABSOLUTE_PATH = File.expand_path(File.dirname(__FILE__))

COMPILE_TARGET = 'release'
PRODUCT = "Rackspace Cloud Server Agent"
COPYRIGHT = "Copyright (c) 2009 2010 2011, Rackspace Cloud.  All Rights Reserved";
COMPANY = "Rackspace Cloud"
DESCRIPTION = "C#.NET Agent for Windows Virtual Machines"
CLR_VERSION = 'v3.5'
RELEASE_BUILD_NUMBER = "1.2.5.0"

#Paths
SLN_FILE = File.join(ABSOLUTE_PATH,'src','WindowsConfigurationAgent.sln')
AGENT_UNIT_TEST_DLL = File.join(ABSOLUTE_PATH,'src','Rackspace.Cloud.Server.Agent.Specs','bin',COMPILE_TARGET,'Rackspace.Cloud.Server.Agent.Specs.dll')
DIFFIEHELLMAN_UNIT_TEST_DLL = File.join(ABSOLUTE_PATH,'src','Rackspace.Cloud.Server.DiffieHellman.Specs','bin',COMPILE_TARGET,'Rackspace.Cloud.Server.DiffieHellman.Specs.dll')
AGENT_SERVICE_DIR = File.join(ABSOLUTE_PATH,'src','Rackspace.Cloud.Server.Agent.Service','bin','Release')
UPDATE_SERVICE_DIR = File.join(ABSOLUTE_PATH,'src','Rackspace.Cloud.Server.Agent.UpdaterService','bin','Release')
BUILDS_DIR = File.join(ABSOLUTE_PATH,'builds')
NUNIT_CMD_EXE = File.join(ABSOLUTE_PATH,'lib','nunit','nunit-console.exe')
FRAMEWORK_DIR = File.join(ENV['windir'].dup, 'Microsoft.NET', 'Framework', CLR_VERSION)
MSBUILD_EXE = File.join(FRAMEWORK_DIR, 'msbuild.exe')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,7 +6,7 @@
 COMPANY = "Rackspace Cloud"
 DESCRIPTION = "C#.NET Agent for Windows Virtual Machines"
 CLR_VERSION = 'v3.5'
-RELEASE_BUILD_NUMBER = "1.2.5.0"
+RELEASE_BUILD_NUMBER = "1.2.6.0"
 
 #Paths
 SLN_FILE = File.join(ABSOLUTE_PATH,'src','WindowsConfigurationAgent.sln')
```
