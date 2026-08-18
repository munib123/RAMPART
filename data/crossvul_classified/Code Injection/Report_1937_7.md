# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in yaml
**Pair ID:** 1937_7
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** yaml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1937_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```yaml
Lines 1-36 of the vulnerable file.

apiVersion: v1
entries:
  alpine:
    - name: alpine
      urls:
        - https://charts.helm.sh/stable/alpine-0.1.0.tgz
      checksum: 0e6661f193211d7a5206918d42f5c2a9470b737d
      home: https://helm.sh/helm
      sources:
        - https://github.com/helm/helm
      version: 0.2.0
      description: Deploy a basic Alpine Linux pod
      keywords: []
      maintainers: []
      icon: ""
    - name: alpine
      urls:
        - https://charts.helm.sh/stable/alpine-0.2.0.tgz
      checksum: 0e6661f193211d7a5206918d42f5c2a9470b737d
      home: https://helm.sh/helm
      sources:
        - https://github.com/helm/helm
      version: 0.1.0
      description: Deploy a basic Alpine Linux pod
      keywords: []
      maintainers: []
      icon: ""
  mariadb:
    - name: mariadb
      urls:
        - https://charts.helm.sh/stable/mariadb-0.3.0.tgz
      checksum: 65229f6de44a2be9f215d11dbff311673fc8ba56
      home: https://mariadb.org
      sources:
        - https://github.com/bitnami/bitnami-docker-mariadb
      version: 0.3.0
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,7 @@
       keywords: []
       maintainers: []
       icon: ""
+      apiVersion: v2
     - name: alpine
       urls:
         - https://charts.helm.sh/stable/alpine-0.2.0.tgz
@@ -25,6 +26,7 @@
       keywords: []
       maintainers: []
       icon: ""
+      apiVersion: v2
   mariadb:
     - name: mariadb
       urls:
@@ -44,3 +46,4 @@
         - name: Bitnami
           email: containers@bitnami.com
       icon: ""
+      apiVersion: v2
```
