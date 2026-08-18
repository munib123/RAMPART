# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in yaml
**Pair ID:** 4205_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** yaml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4205_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```yaml
Lines 1-20 of the vulnerable file.

name: 'Git Tag Annotation'
description: 'Get the annotation associated with a git tag'
author: 'Eric Cornelissen'

inputs:
  tag:
    description: 'tag of interest (defaults to the GITHUB_REF environment variable)'
    required: false

outputs:
  git-tag-annotation:
    description: 'The git tag annotation'

runs:
  using: 'node12'
  main: 'lib/index.js'

branding:
  icon: 'git-commit'
  color: 'gray-dark'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,5 +16,5 @@
   main: 'lib/index.js'
 
 branding:
-  icon: 'git-commit'
+  icon: 'tag'
   color: 'gray-dark'
```
