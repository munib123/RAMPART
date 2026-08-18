# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in css
**Pair ID:** 1187_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** css
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1187_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```css
Lines 457-513 of the vulnerable file.

  bottom: 100%;
  left: 0;
  right: -1px;
  padding: 5px 0 2px;
  border: 1px solid var(--barBorderColor);
  background-color: var(--leakColor);
  font-size: var(--mediumFontSize);
  text-align: center;
  transform: translateY(-4px);
}

.overview-legend-spaced-line {
  padding: 14px 0 10px;
}

.overview-key {
  width: 100%;
  background-color: transparent !important;
}

.copy-paste-link .overview-key {
  width: 90%;
}

.copy-paste-link .close {
  color: #000;
  border-bottom: 0;
  height: 100%;
  display: inline-block;
  margin-left: 5px;
  box-sizing: border-box;
}

.copy-paste-link .close svg {
  vertical-align: sub;
}

.overview-deleted-profile,
.overview-deprecated-rules {
  margin: 4px -6px 4px;
  padding: 3px 6px !important;
  border: 1px solid #ebccd1;
  border-radius: 3px;
  background-color: #f2dede;
}

/*
 * Animations
 */

@keyframes fadeIn {
  from {
    opacity: 0;
  }

  to {
    opacity: 1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -474,23 +474,6 @@
   background-color: transparent !important;
 }
 
-.copy-paste-link .overview-key {
-  width: 90%;
-}
-
-.copy-paste-link .close {
-  color: #000;
-  border-bottom: 0;
-  height: 100%;
-  display: inline-block;
-  margin-left: 5px;
-  box-sizing: border-box;
-}
-
-.copy-paste-link .close svg {
-  vertical-align: sub;
-}
-
 .overview-deleted-profile,
 .overview-deprecated-rules {
   margin: 4px -6px 4px;
```
