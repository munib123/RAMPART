# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in html
**Pair ID:** 4361_2
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4361_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```html
Lines 151-191 of the vulnerable file.

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
      <img class="logo" src="assets/logo.png">
      <div class="title">systeminformation</div>
      <div class="subtitle"><span id="typed"></span></div>
      <div class="version">Current Version: <span id="version">4.30.4</span></div>
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
          <a href="https://david-dm.org/sebhildebrandt/systeminformation" rel="nofollow"><img src="https://camo.githubusercontent.com/69739c043c2be3a38545f105b89381a2a6310f59/68747470733a2f2f696d672e736869656c64732e696f2f64617669642f73656268696c64656272616e64742f73797374656d696e666f726d6174696f6e2e7376673f7374796c653d666c61742d737175617265" alt="deps status" data-canonical-src="https://img.shields.io/david/sebhildebrandt/systeminformation.svg?style=flat-square" style="max-width:100%;"></a>
          <a href="https://lgtm.com/projects/g/sebhildebrandt/systeminformation/context:javascript" rel="nofollow"><img src="https://camo.githubusercontent.com/08409d6fb3794545416e1a40ca75172b54d34692/68747470733a2f2f696d672e736869656c64732e696f2f6c67746d2f67726164652f6a6176617363726970742f672f73656268696c64656272616e64742f73797374656d696e666f726d6174696f6e2e7376673f7374796c653d666c61742d737175617265" alt="Code Quality: Javascript" data-canonical-src="https://img.shields.io/lgtm/grade/javascript/g/sebhildebrandt/systeminformation.svg?style=flat-square" style="max-width:100%;"></a>
          <a href="https://lgtm.com/projects/g/sebhildebrandt/systeminformation/alerts" rel="nofollow"><img src="https://camo.githubusercontent.com/66428127fdde80fc8247a0c1df4c651f3a6b1c0a/68747470733a2f2f696d672e736869656c64732e696f2f6c67746d2f616c657274732f672f73656268696c64656272616e64742f73797374656d696e666f726d6174696f6e2e7376673f7374796c653d666c61742d737175617265" alt="Total alerts" data-canonical-src="https://img.shields.io/lgtm/alerts/g/sebhildebrandt/systeminformation.svg?style=flat-square" style="max-width:100%;"></a>
          <a href="https://github.com/sebhildebrandt/systeminformation/blob/master/LICENSE"><img src="https://camo.githubusercontent.com/4b5966a2a252ee0f241a1e03b13417178eb4964f/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f6c6963656e73652d4d49542d626c75652e7376673f7374796c653d666c61742d737175617265" alt="MIT license" data-canonical-src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square" style="max-width:100%;"></a>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -168,7 +168,7 @@
       <img class="logo" src="assets/logo.png">
       <div class="title">systeminformation</div>
       <div class="subtitle"><span id="typed"></span></div>
-      <div class="version">Current Version: <span id="version">4.30.4</span></div>
+      <div class="version">Current Version: <span id="version">4.30.5</span></div>
       <button class="btn btn-light" onclick="location.href='https://github.com/sebhildebrandt/systeminformation'">View on Github <i class=" fab fa-github"></i></button>
     </div>
     <div class="down">
```
