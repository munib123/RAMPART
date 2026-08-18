# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in csharp
**Pair ID:** 5811_3
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5811_3`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```csharp
Lines 1-7 of the vulnerable file.

using System.Reflection;
using System.Runtime.InteropServices;
[assembly: AssemblyDescription("C#.NET Agent for Windows Virtual Machines")]
[assembly: AssemblyCompany("Rackspace Cloud")]
[assembly: AssemblyProduct("Rackspace Cloud Server Agent")]
[assembly: AssemblyCopyright("Copyright (c) 2009 2010 2011, Rackspace Cloud.  All Rights Reserved")]
[assembly: AssemblyVersion("1.2.5.0")]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,4 +4,4 @@
 [assembly: AssemblyCompany("Rackspace Cloud")]
 [assembly: AssemblyProduct("Rackspace Cloud Server Agent")]
 [assembly: AssemblyCopyright("Copyright (c) 2009 2010 2011, Rackspace Cloud.  All Rights Reserved")]
-[assembly: AssemblyVersion("1.2.5.0")]
+[assembly: AssemblyVersion("1.2.6.0")]
```
