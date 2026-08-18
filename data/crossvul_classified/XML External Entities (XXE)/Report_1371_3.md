# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in yaml
**Pair ID:** 1371_3
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** yaml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1371_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```yaml
Lines 1-21 of the vulnerable file.

version: 1.5.7.{build}
environment:
  my_version: 1.5.7
  my_secret:
    secure: vbPRaZLQYpGPr4BrZZ4p6TofpSZMud+FKtlpqjgO8aA=
skip_branch_with_pr: true
image: Visual Studio 2017
clone_folder: c:\projects\AutoUpdater.NET
build: off
install:
- nuget install secure-file -ExcludeVersion
- cmd: nuget restore
- secure-file\tools\secure-file -decrypt "c:\projects\AutoUpdater.NET\ZipExtractor\ZipExtractor.snk.enc" -secret %my_secret%
- secure-file\tools\secure-file -decrypt "c:\projects\AutoUpdater.NET\AutoUpdater.NET\AutoUpdater.NET.snk.enc" -secret %my_secret%
- msbuild "c:\projects\AutoUpdater.NET\ZipExtractor\ZipExtractor.csproj" /p:Configuration=Release /verbosity:minimal /logger:"C:\Program Files\AppVeyor\BuildAgent\Appveyor.MSBuildLogger.dll"
- msbuild "c:\projects\AutoUpdater.NET\AutoUpdater.NET\AutoUpdater.NET.csproj" /p:Configuration=Release /verbosity:minimal /logger:"C:\Program Files\AppVeyor\BuildAgent\Appveyor.MSBuildLogger.dll"
- msbuild "c:\projects\AutoUpdater.NET\ZipExtractor\ZipExtractor.csproj" /p:Configuration=Release-NET35 /verbosity:minimal /logger:"C:\Program Files\AppVeyor\BuildAgent\Appveyor.MSBuildLogger.dll"
- msbuild "c:\projects\AutoUpdater.NET\AutoUpdater.NET\AutoUpdater.NET.csproj" /p:Configuration=Release-NET35 /verbosity:minimal /logger:"C:\Program Files\AppVeyor\BuildAgent\Appveyor.MSBuildLogger.dll"
- msbuild "c:\projects\AutoUpdater.NET\ZipExtractor\ZipExtractor.csproj" /p:Configuration=Release-NET40 /verbosity:minimal /logger:"C:\Program Files\AppVeyor\BuildAgent\Appveyor.MSBuildLogger.dll"
- msbuild "c:\projects\AutoUpdater.NET\AutoUpdater.NET\AutoUpdater.NET.csproj" /p:Configuration=Release-NET40 /verbosity:minimal /logger:"C:\Program Files\AppVeyor\BuildAgent\Appveyor.MSBuildLogger.dll"
- nuget pack "c:\projects\AutoUpdater.NET\AutoUpdater.NET\build\Autoupdater.NET.Official.nuspec"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
-version: 1.5.7.{build}
+version: 1.5.8.{build}
 environment:
-  my_version: 1.5.7
+  my_version: 1.5.8
   my_secret:
     secure: vbPRaZLQYpGPr4BrZZ4p6TofpSZMud+FKtlpqjgO8aA=
 skip_branch_with_pr: true
```
