# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 2055_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2055_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 1-28 of the vulnerable file.

<!doctype HTML>
<html>
    <head>
        <title>Changes</title>
    </head>
    <body>
        <ul>
            <li>
                2.4.18 21.09.13
                <br/>
                Removed two sets of XSS vulnerabilities:
                <br/>
                - XSS due to lack of validation in easyxdm.as - disclosed responsibly by Jakob Heuser (LinkedIn)
                <br/>
                - XSS due to lack of validation in easyxdm.as (CVE-2013-5212) - disclosed by Krzystof Kotowicz (Cure53)
                <br/>				
                +++ See commit log
            </li>
            <li>
                2.4.16 09.02.12
                <br/>
                Improved many of the samples</br>
                Fixed issues with logging</br>
                Added support for posting to the initial src</br>
                Several minor bugfixes</br>
                +++ See commit log
            </li>
            <li>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,13 @@
     </head>
     <body>
         <ul>
+             <li>
+                2.4.19 18.01.14
+                <br/>
+                Removed XSS vulnerability:
+                <br/>
+                - XSS due to lack of validation in name.html (CVE-2014-1403) - disclosed by Krzystof Kotowicz (Cure53)
+            </li>
             <li>
                 2.4.18 21.09.13
                 <br/>
```
