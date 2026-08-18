# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 4275_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4275_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 112-166 of the vulnerable file.


i.fa.fa-bars:hover{
  color: #6e707e;
}

.info-item {
  width: 10rem;
  float: left;
}

.info-item-xs {
  font-size: 0.7rem;
  margin-left: 0.3rem;
}

.info-item-wifi {
  width: 6rem;
  float: left;
}

.webconsole {
  width:100%;
  height:100%;
  border:1px solid;
}

#console {
  height:500px;
}

.systemtabcontent {
  height:100%;
  min-height:500px;
}

.service-status {
  border-width: 0;
}

.service-status-up {
  color: #a1ec38;
}

.service-status-warn {
  color: #f6f044;
}

.service-status-down {
  color: #f80107;
  animation: flash 1s linear infinite;
}
@keyframes flash {
  50% {
    opacity: 0;
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -129,21 +129,6 @@
   float: left;
 }
 
-.webconsole {
-  width:100%;
-  height:100%;
-  border:1px solid;
-}
-
-#console {
-  height:500px;
-}
-
-.systemtabcontent {
-  height:100%;
-  min-height:500px;
-}
-
 .service-status {
   border-width: 0;
 }
```
