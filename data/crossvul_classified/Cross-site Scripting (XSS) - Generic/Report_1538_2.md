# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1538_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1538_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-21 of the vulnerable file.

/* globals BaseUI, CardsHelper, TrustedUIManager */

/* exported Card */

'use strict';

(function(exports) {

  var _id = 0;

  /**
   * A card in a card view, representing a single app
   *
   * @class Card
   * @param {Object} config config to associate the card with a given app and
   *                        how it should be displayed
   * @extends BaseUI
   */
  function Card(config) {
    if (config) {
      for (var key in config) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* globals BaseUI, CardsHelper, TrustedUIManager */
+/* globals BaseUI, CardsHelper, Tagged, TrustedUIManager */
 
 /* exported Card */
 
@@ -69,38 +69,40 @@
    * Template string representing the innerHTML of the instance's element
    * @memberOf Card.prototype
    */
-  Card.prototype._template =
-    '<div class="titles">' +
-    ' <h1 id="{titleId}" class="title">{title}</h1>' +
-    ' <p class="subtitle">{subTitle}</p>' +
-    '</div>' +
-    '' +
-    '<div class="screenshotView bb-button" data-l10n-id="openCard" ' +
-    '  role="link"></div>' +
-    '<div class="appIconView" style="background-image:{iconValue}"></div>' +
-    '' +
-    '<footer class="card-tray">'+
-    ' <button class="appIcon" data-l10n-id="openCard" ' +
-    '   data-button-action="select" aria-hidden="true"></button>' +
-    ' <menu class="buttonbar">' +
-    '   <button class="close-button bb-button" data-l10n-id="closeCard" ' +
-    '     data-button-action="close" role="button" ' +
-    '     style="visibility: {closeButtonVisibility}"></button>' +
-    '  <button class="favorite-button bb-button" ' +
-    '    data-button-action="favorite" role="button" ' +
-    '    style="visibility: {favoriteButtonVisibility}"></button>' +
-    ' </menu>' +
-    '</footer>';
+  Card.prototype.template = function() {
+    // fix a jshint issue with tagged template strings
+    // https://github.com/jshint/jshint/issues/2000
+    /* jshint -W033 */
+    return Tagged.escapeHTML `<div class="titles">
+     <h1 id="${this.titleId}" class="title">${this.title}</h1>
+     <p class="subtitle">${this.subTitle}</p>
+    </div>
+
+    <div class="screenshotView bb-button" data-l10n-id="openCard"
+      role="link"></div>
+    <div class="appIconView" style="background-image:${this.iconValue}"></div>
+
+    <footer class="card-tray">
+     <button class="appIcon" data-l10n-id="openCard"
+       data-button-action="select" aria-hidden="true"></button>
+     <menu class="buttonbar">
+       <button class="close-button bb-button" data-l10n-id="closeCard"
+         data-button-action="close" role="button"
+         style="visibility: ${this.closeButtonVisibility}"></button>
+      <button class="favorite-button bb-button"
+        data-button-action="favorite" role="button"
+        style="visibility: ${this.favoriteButtonVisibility}"></button>
+     </menu>
+    </footer>`;
+    /* jshint +W033 */
+  };
 
   /**
    * Card html view - builds the innerHTML for a card element
    * @memberOf Card.prototype
    */
   Card.prototype.view = function c_view() {
-    var viewData = this;
-    return this._template.replace(/\{([^\}]+)\}/g, function(m, key) {
-        return viewData[key];
-    });
+    return this.template();
   };
 
   /**
```
