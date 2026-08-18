# CrossVul Fix Pair: Out-of-bounds Read in yaml
**Pair ID:** 1282_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** yaml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1282_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```yaml
Lines 1-27 of the vulnerable file.

environment:
  matrix:
    # For Python versions available on Appveyor, see
    # http://www.appveyor.com/docs/installed-software#python
    - PYTHON: "C:\\Python33"
    - PYTHON: "C:\\Python33-x64"
      DISTUTILS_USE_SDK: 1
    - PYTHON: "C:\\Python34"
    - PYTHON: "C:\\Python34-x64"
      DISTUTILS_USE_SDK: 1
    - PYTHON: "C:\\Python35"
    - PYTHON: "C:\\Python35-x64"
    - PYTHON: "C:\\Python36"
    - PYTHON: "C:\\Python36-x64"
    - PYTHON: "C:\\Python37"
    - PYTHON: "C:\\Python37-x64"

install:
  # We need wheel installed to build wheels
  - "%PYTHON%\\python.exe -m pip install wheel"

build: off

test_script:
  # Put your test command here.
  # If you don't need to build C extensions on 64-bit Python 3.3 or 3.4,
  # you can remove "build.cmd" from the front of the command, as it's
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,9 +2,6 @@
   matrix:
     # For Python versions available on Appveyor, see
     # http://www.appveyor.com/docs/installed-software#python
-    - PYTHON: "C:\\Python33"
-    - PYTHON: "C:\\Python33-x64"
-      DISTUTILS_USE_SDK: 1
     - PYTHON: "C:\\Python34"
     - PYTHON: "C:\\Python34-x64"
       DISTUTILS_USE_SDK: 1
```
