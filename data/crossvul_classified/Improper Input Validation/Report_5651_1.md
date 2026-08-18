# CrossVul Fix Pair: Improper Input Validation in yaml
**Pair ID:** 5651_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** yaml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5651_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```yaml
Lines 8-28 of the vulnerable file.

  Test::More: 0
configure_requires:
  ExtUtils::MakeMaker: 6.36
distribution_type: module
dynamic_config: 1
generated_by: 'Module::Install version 1.06'
license: cc0
meta-spec:
  url: http://module-build.sourceforge.net/META-spec-v1.4.html
  version: 1.4
name: Module-Signature
no_index:
  directory:
    - inc
    - t
requires:
  IO::Socket::INET: 0
  perl: 5.005
resources:
  repository: http://github.com/audreyt/module-signature
version: 0.70
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,4 +25,4 @@
   perl: 5.005
 resources:
   repository: http://github.com/audreyt/module-signature
-version: 0.70
+version: 0.71
```
