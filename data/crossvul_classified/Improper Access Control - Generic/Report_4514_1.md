# CrossVul Fix Pair: Improper Access Control in yaml
**Pair ID:** 4514_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** yaml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4514_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```yaml
Lines 1-15 of the vulnerable file.

apiVersion: v1
name: conjur-oss
home: https://www.conjur.org
version: 1.3.8
description: A Helm chart for CyberArk Conjur
icon: https://www.cyberark.com/wp-content/uploads/2015/12/cybr-aim.jpg
keywords:
  - security
  - 'secrets management'
sources:
  - https://github.com/cyberark/conjur-oss-helm-chart
  - https://github.com/cyberark/conjur
maintainers:
  - name: Conjur Maintainers
    email: conj_maintainers@cyberark.com
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 apiVersion: v1
 name: conjur-oss
 home: https://www.conjur.org
-version: 1.3.8
+version: 2.0.0
 description: A Helm chart for CyberArk Conjur
 icon: https://www.cyberark.com/wp-content/uploads/2015/12/cybr-aim.jpg
 keywords:
```
