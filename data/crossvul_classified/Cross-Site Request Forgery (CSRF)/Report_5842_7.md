# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in html
**Pair ID:** 5842_7
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5842_7`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```html
Lines 1-19 of the vulnerable file.

<wicket:panel xmlns:wicket="http://wicket.apache.org/dtds.data/wicket-xhtml1.4-strict.dtd">
  <div class="modal hide" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true" wicket:id="mainContainer">
    <wicket:container wicket:id="mainSubContainer">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>
        <h3 id="myModalLabel" wicket:id="titleContainer"><span wicket:id="titleText">[title]</span></h3>
      </div>
      <form wicket:id="form" autocomplete="off">
        <div class="modal-body" wicket:id="gridContent">
          <div wicket:id="formFeedback"></div>
          <wicket:container wicket:id="flowform">[The content]</wicket:container>
        </div>
        <div class="modal-footer" wicket:id="buttonBar">
          <wicket:container wicket:id="actionButtons" />
        </div>
      </form>
    </wicket:container>
  </div>
</wicket:panel>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,9 @@
     <wicket:container wicket:id="mainSubContainer">
       <div class="modal-header">
         <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>
-        <h3 id="myModalLabel" wicket:id="titleContainer"><span wicket:id="titleText">[title]</span></h3>
+        <h3 id="myModalLabel" wicket:id="titleContainer">
+          <span wicket:id="titleText">[title]</span>
+        </h3>
       </div>
       <form wicket:id="form" autocomplete="off">
         <div class="modal-body" wicket:id="gridContent">
@@ -13,6 +15,7 @@
         <div class="modal-footer" wicket:id="buttonBar">
           <wicket:container wicket:id="actionButtons" />
         </div>
+        <input type="hidden" wicket:id="csrfToken" />
       </form>
     </wicket:container>
   </div>
```
