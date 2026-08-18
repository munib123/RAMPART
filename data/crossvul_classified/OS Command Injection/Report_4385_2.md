# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in html
**Pair ID:** 4385_2
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4385_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```html
Lines 148-188 of the vulnerable file.


        if (window.pageYOffset === destinationOffsetToScroll) {
          if (callback) {
            callback();
          }
          return;
        }

        requestAnimationFrame(scroll);
      }

      scroll();
    }
  </script>

</head>

<body>
  <header class="bg-image-full">
    <div class="container">
      <a href="security.html" class="recommendation">Security advisory:<br>Update to v4.30.5</a>
      <img class="logo" src="assets/logo.png">
      <div class="title">systeminformation</div>
      <div class="subtitle"><span id="typed"></span></div>
      <div class="version">Current Version: <span id="version">4.31.0</span></div>
      <button class="btn btn-light" onclick="location.href='https://github.com/sebhildebrandt/systeminformation'">View on Github <i class=" fab fa-github"></i></button>
    </div>
    <div class="down">
      <button class="btn btn-primary mb-2" onclick="location.href='https://www.buymeacoffee.com/systeminfo'">Buy me a coffee&nbsp;&nbsp;<i class="far fa-mug-hot"></i></button>
      <br>Read Documentation<br>
      <i class="fal fa-caret-down caret"></i>
    </div>
  </header>

  <section class="container quickstart">
    <div class="row">
      <div class="col-12 sectionheader index">
        <div class="title">Overview</div>
        <div class="subtitle">Lightweight collection of 40+ functions to retrieve detailed hardware, system and OS information. For Linux, macOS, partial Windows, FreeBSD, OpenBSD, NetBSD and SunOS support</div>
        <div class="npmicons">
          <a href="https://npmjs.org/package/systeminformation" rel="nofollow"><img src="https://camo.githubusercontent.com/df25636cbefadf18ca1532e3bdcd0d2794235e19/68747470733a2f2f696d672e736869656c64732e696f2f6e706d2f762f73797374656d696e666f726d6174696f6e2e7376673f7374796c653d666c61742d737175617265" alt="NPM Version" data-canonical-src="https://img.shields.io/npm/v/systeminformation.svg?style=flat-square" style="max-width:100%;"></a>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -165,11 +165,11 @@
 <body>
   <header class="bg-image-full">
     <div class="container">
-      <a href="security.html" class="recommendation">Security advisory:<br>Update to v4.30.5</a>
+      <a href="security.html" class="recommendation">Security advisory:<br>Update to v4.31.1</a>
       <img class="logo" src="assets/logo.png">
       <div class="title">systeminformation</div>
       <div class="subtitle"><span id="typed"></span></div>
-      <div class="version">Current Version: <span id="version">4.31.0</span></div>
+      <div class="version">Current Version: <span id="version">4.31.1</span></div>
       <button class="btn btn-light" onclick="location.href='https://github.com/sebhildebrandt/systeminformation'">View on Github <i class=" fab fa-github"></i></button>
     </div>
     <div class="down">
```
