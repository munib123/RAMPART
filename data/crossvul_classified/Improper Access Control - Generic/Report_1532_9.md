# CrossVul Fix Pair: Improper Access Control in css
**Pair ID:** 1532_9
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** css
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1532_9`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```css
Lines 1-27 of the vulnerable file.

/* Don't let page CSS bleed into our modals. */

/* The dialog itself, and common elements on every dialog page (like the title bar) */
.adblock-whitelist-dialog {
  z-index: 10000;
  padding: 0px;
}
.ui-dialog a[href] {
  text-decoration: underline !important;
}
.ui-dialog * {
  font-size: 12px !important;
  font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
  color: #222;
  margin-top: 0px;
}
.ui-dialog span.ui-dialog-title {
  color: black !important;
  display: block !important;
}
.ui-dialog .ui-dialog-titlebar {
  display: block !important;
  padding-left: 48px !important;
  background-image: url(../../img/icon24.png) !important;
  background-repeat: no-repeat;
  background-position: 2%;
  width: auto !important;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,9 @@
 .adblock-whitelist-dialog {
   z-index: 10000;
   padding: 0px;
+}
+.ui-button-text {
+  display: block !important;
 }
 .ui-dialog a[href] {
   text-decoration: underline !important;
@@ -59,7 +62,10 @@
   outline: none;
   box-shadow: none;
 }
-.ui-dialog.ui-state-hover button {
+.ui-dialog .ui-corner-all {
+  border-radius: 5px;
+}
+.ui-dialog .ui-state-hover button {
   background: #79C9EC !important;
 }
 .ui-dialog .ui-dialog-titlebar-close {
@@ -83,7 +89,7 @@
 .ui-dialog label {
   cursor: pointer;
 }
-.ui-dialog .ui-dialog-buttonpane { 
+.ui-dialog .ui-dialog-buttonpane {
   display: block !important;
   background-color: white;
   margin: 0px;
```
