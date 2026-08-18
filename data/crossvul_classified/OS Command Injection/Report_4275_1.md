# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in css
**Pair ID:** 4275_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** css
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4275_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```css
Lines 340-389 of the vulnerable file.

.progress {
  background-color: #202020;
  border-radius: 0px;
}

.progress-bar {
  color: #202020;
}

.progress-bar.progress-bar-info.progress-bar-striped.active {
  background-color: #d2d2d2;
}

.logoutput {
  width: 100%;
  height: 300px;
  background-color: #202020;
  border-color: #404040;
}

.webconsole {
  width: 100%;
  height: 20rem;
  border: 1px solid #404040;
}

#console {
  height: 500px;
}

tspan, rect {
  fill: #d2d2d2;
}

span.text.service-status {
  font-size: 0.75rem;
  margin-top: 0.2rem;
}

.text-muted {
  font-size: 0.8rem;
}

.fas.fa-circle {
  font-size: 0.5rem;
}

.service-status-up {
  color: #a1ec38 !important;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -357,16 +357,6 @@
   border-color: #404040;
 }
 
-.webconsole {
-  width: 100%;
-  height: 20rem;
-  border: 1px solid #404040;
-}
-
-#console {
-  height: 500px;
-}
-
 tspan, rect {
   fill: #d2d2d2;
 }
```
