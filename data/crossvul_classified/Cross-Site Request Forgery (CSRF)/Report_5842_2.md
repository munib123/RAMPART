# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in html
**Pair ID:** 5842_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5842_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```html
Lines 4-40 of the vulnerable file.

</head>

<body>
  <wicket:extend>
    <div class="tabbable">
      <ul class="nav nav-tabs">
        <li class="active"><a href="#setupform" data-toggle="tab"><wicket:message key="administration.setup" /></a></li>
        <li><a href="#upload" data-toggle="tab"><wicket:message key="import" /></a></li>
      </ul>
    </div>
    <div class="tab-content">
      <div id="setupform" class="tab-pane active">

        <div id="setupform" class="section">
          <form wicket:id="setupform" autocomplete="off">
            <div wicket:id="feedback"></div>
            <wicket:container wicket:id="flowform">[the form fields]</wicket:container>
            <div class="button_bar">
              <wicket:container wicket:id="buttons">[action buttons]</wicket:container>
            </div>
          </form>
        </div>
      </div>

      <div id="upload" class="tab-pane">
        <form wicket:id="importform" autocomplete="off">
          <div wicket:id="feedback"></div>
          <wicket:container wicket:id="flowform">[the form fields]</wicket:container>
          <div class="button_bar">
            <wicket:container wicket:id="buttons">[action buttons]</wicket:container>
          </div>
        </form>
      </div>
    </div>
  </wicket:extend>
</body>
</html>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,6 +21,7 @@
             <div class="button_bar">
               <wicket:container wicket:id="buttons">[action buttons]</wicket:container>
             </div>
+            <input type="hidden" wicket:id="csrfToken" />
           </form>
         </div>
       </div>
@@ -32,6 +33,7 @@
           <div class="button_bar">
             <wicket:container wicket:id="buttons">[action buttons]</wicket:container>
           </div>
+          <input type="hidden" wicket:id="csrfToken" />
         </form>
       </div>
     </div>
```
