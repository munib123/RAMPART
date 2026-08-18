# CrossVul Fix Pair: Missing Encryption of Sensitive Data in javascript
**Pair ID:** 2892_0
**Vulnerability Class:** Missing Encryption of Sensitive Data
**CWE:** CWE-311
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2892_0`)

## Vulnerability Information & PoC

## Description
Missing Encryption of Sensitive Data - The lack of proper data encryption passes up the guarantees of confidentiality, integrity, and accountability that properly implemented encryption conveys.

## Vulnerable Code
```javascript
Lines 1-19 of the vulnerable file.

var pythonMirror = process.env.npm_config_python_mirror || process.env.PYTHON_MIRROR || 'https://www.python.org/ftp/python/'

var buildTools = {
  installerName: 'BuildTools_Full.exe',
  installerUrl: 'http://download.microsoft.com/download/5/f/7/5f7acaeb-8363-451f-9425-68a90f98b238/visualcppbuildtools_full.exe',
  logName: 'build-tools-log.txt'
}

var python = {
  installerName: 'python-2.7.11.msi',
  installerUrl: pythonMirror.replace(/\/*$/, '/2.7.11/python-2.7.11.msi'),
  targetName: 'python27',
  logName: 'python-log.txt'
}

module.exports = {
  buildTools,
  python
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
 
 var buildTools = {
   installerName: 'BuildTools_Full.exe',
-  installerUrl: 'http://download.microsoft.com/download/5/f/7/5f7acaeb-8363-451f-9425-68a90f98b238/visualcppbuildtools_full.exe',
+  installerUrl: 'https://download.microsoft.com/download/5/f/7/5f7acaeb-8363-451f-9425-68a90f98b238/visualcppbuildtools_full.exe',
   logName: 'build-tools-log.txt'
 }
 
```
