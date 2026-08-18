# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 870_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `870_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-23 of the vulnerable file.

/**
  shave - Shave is a javascript plugin that truncates multi-line text within a html element based on set max height
  @version v2.5.2
  @link https://github.com/dollarshaveclub/shave#readme
  @author Jeff Wainwright <yowainwright@gmail.com> (jeffry.in)
  @license MIT
**/
(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() :
  typeof define === 'function' && define.amd ? define(factory) :
  (global.shave = factory());
}(this, (function () { 'use strict';

  function shave(target, maxHeight) {
    var opts = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};
    if (!maxHeight) throw Error('maxHeight is required');
    var els = typeof target === 'string' ? document.querySelectorAll(target) : target;
    if (!els) return;
    var character = opts.character || '…';
    var classname = opts.classname || 'js-shave';
    var spaces = typeof opts.spaces === 'boolean' ? opts.spaces : true;
    var charHtml = "<span class=\"js-shave-char\">".concat(character, "</span>");
    if (!('length' in els)) els = [els];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 /**
   shave - Shave is a javascript plugin that truncates multi-line text within a html element based on set max height
-  @version v2.5.2
+  @version v2.5.3
   @link https://github.com/dollarshaveclub/shave#readme
   @author Jeff Wainwright <yowainwright@gmail.com> (jeffry.in)
   @license MIT
@@ -67,7 +67,12 @@
       el[textProp] = spaces ? words.slice(0, max).join(' ') : words.slice(0, max);
       el.insertAdjacentHTML('beforeend', charHtml);
       var diff = spaces ? " ".concat(words.slice(max).join(' ')) : words.slice(max);
-      el.insertAdjacentHTML('beforeend', "<span class=\"".concat(classname, "\" style=\"display:none;\">").concat(diff, "</span>"));
+      var shavedText = document.createTextNode(diff);
+      var elWithShavedText = document.createElement('span');
+      elWithShavedText.classList.add(classname);
+      elWithShavedText.style.display = 'none';
+      elWithShavedText.appendChild(shavedText);
+      el.insertAdjacentElement('beforeend', elWithShavedText);
       styles.height = heightStyle;
       styles.maxHeight = maxHeightStyle;
     }
```
