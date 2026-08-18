# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in html
**Pair ID:** 4385_3
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4385_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```html
Lines 25-65 of the vulnerable file.

<body>
  <nav class="nav">
    <div class="container">
      <a href="."><img class="logo float-left" src="assets/logo.png">
        <div class="title float-left">systeminformation</div>
      </a>
      <div class="text float-right github"><a href="https://github.com/sebhildebrandt/systeminformation">View on Github <i class="fab fa-github"></i></a></div>
      <div class="text float-right todocs"><a href="./#docs">Docs Overview</a></div>
    </div>
  </nav>

  <section class="container">
    <div class="row">
      <div class="col-12 col-md-4 col-lg-3 col-xl-2 menu" id="menu">
      </div>
      <div class="col-12 col-md-8 col-lg-9 col-xl-10 content">
        <div class="row">
          <div class="col-12 sectionheader">
            <div class="title">Security Advisories</div>
            <div class="text">
              <h2>command injection vulnerability - prototype pollution</h2>
              <p><span class="bold">Affected versions:</span>
                < 4.30.5<br>
                  <span class="bold">Date:</span> 2020-11-26<br>
                  <span class="bold">CVE indentifier</span> CVE-2020-26245
              </p>

              <h4>Impact</h4>
              <p>Here we had an issue that there was a possibility to inject commands to the command line by property pollution on the string object. Affected commands: <span class="code">inetChecksite()</span>.</p>

              <h4>Patch</h4>
              <p>Problem was fixed with a shell string sanitation fix as well as handling prototype polution. Please upgrade to version >= 4.30.5</p>

              <h4>Workarround</h4>
              <p>If you cannot upgrade, be sure to check or sanitize service parameter strings that are passed to <span class="code">inetChecksite()</span></p>


              <h2>Command Injection Vulnerability</h2>
              <p><span class="bold">Affected versions:</span>
                < 4.27.11<br>
                  <span class="bold">Date:</span> 2020-10-26<br>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,6 +42,23 @@
           <div class="col-12 sectionheader">
             <div class="title">Security Advisories</div>
             <div class="text">
+              <h2>Command Injection Vulnerability</h2>
+              <p><span class="bold">Affected versions:</span>
+                < 4.31.1<br>
+                  <span class="bold">Date:</span> 2020-12-11<br>
+                  <span class="bold">CVE indentifier</span> (not yet)
+              </p>
+
+              <h4>Impact</h4>
+              <p>Here we had an issue that there was a possibility to inject commands to the command line of your machine via systeminformation. Affected commands: <span class="code">inetLatency()</span>.</p>
+
+              <h4>Patch</h4>
+              <p>Problem was fixed with a shell string sanitation fix. Please upgrade to version >= 4.31.1</p>
+
+              <h4>Workarround</h4>
+              <p>If you cannot upgrade, be sure to check or sanitize service parameter strings that are passed to <span class="code">inetLatency()</span></p>
+
+
               <h2>command injection vulnerability - prototype pollution</h2>
               <p><span class="bold">Affected versions:</span>
                 < 4.30.5<br>
```
