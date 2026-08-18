# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in csharp
**Pair ID:** 1371_1
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1371_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```csharp
Lines 15-37 of the vulnerable file.

[assembly: AssemblyCulture("")]

// Setting ComVisible to false makes the types in this assembly not visible 
// to COM components.  If you need to access a type in this assembly from 
// COM, set the ComVisible attribute to true on that type.
[assembly: ComVisible(false)]

// The following GUID is for the ID of the typelib if this project is exposed to COM
[assembly: Guid("a4037a6f-fdf7-46c8-a303-c3c4fcddb015")]

// Version information for an assembly consists of the following four values:
//
//      Major Version
//      Minor Version 
//      Build Number
//      Revision
//
// You can specify all the values or you can default the Build and Revision Numbers 
// by using the '*' as shown below:
// [assembly: AssemblyVersion("1.0.*")]
[assembly: AssemblyVersion("1.5.7.0")]
[assembly: AssemblyFileVersion("1.5.7.0")]
[assembly: NeutralResourcesLanguageAttribute("en")]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,6 +32,6 @@
 // You can specify all the values or you can default the Build and Revision Numbers 
 // by using the '*' as shown below:
 // [assembly: AssemblyVersion("1.0.*")]
-[assembly: AssemblyVersion("1.5.7.0")]
-[assembly: AssemblyFileVersion("1.5.7.0")]
+[assembly: AssemblyVersion("1.5.8.0")]
+[assembly: AssemblyFileVersion("1.5.8.0")]
 [assembly: NeutralResourcesLanguageAttribute("en")]
```
