# CrossVul Fix Pair: Improper Input Validation in html
**Pair ID:** 4194_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4194_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```html
Lines 1-22 of the vulnerable file.

<!DOCTYPE html>
<!-- Wire, Copyright (C) 2018 Wire Swiss GmbH -->
<html>
  <head>
    <link rel="stylesheet" href="../css/about.css" />
  </head>
  <body>
    <div>
      <img id="logo" />
      <h1 id="name"></h1>
      <p class="copy"><span data-string="aboutVersion"></span> <span id="version"></span></p>
      <p class="webappVersion copy"><span data-string="aboutWebappVersion"></span> <span id="webappVersion"></span></p>
      <p>
        <a href="https://support.wire.com/hc/articles/115001919905"><span data-string="aboutUpdate"></span></a>
      </p>
      <p>
        <a href="https://medium.com/wire-news/webapp-updates/home"><span data-string="aboutReleases"></span></a>
      </p>
      <p><span id="copyright"></span></p>
    </div>
  </body>
</html>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,10 +11,14 @@
       <p class="copy"><span data-string="aboutVersion"></span> <span id="version"></span></p>
       <p class="webappVersion copy"><span data-string="aboutWebappVersion"></span> <span id="webappVersion"></span></p>
       <p>
-        <a href="https://support.wire.com/hc/articles/115001919905"><span data-string="aboutUpdate"></span></a>
+        <a href="https://support.wire.com/hc/articles/115001919905" target="_blank">
+          <span data-string="aboutUpdate"></span>
+        </a>
       </p>
       <p>
-        <a href="https://medium.com/wire-news/webapp-updates/home"><span data-string="aboutReleases"></span></a>
+        <a href="https://medium.com/wire-news/webapp-updates/home" target="_blank">
+          <span data-string="aboutReleases"></span>
+        </a>
       </p>
       <p><span id="copyright"></span></p>
     </div>
```
