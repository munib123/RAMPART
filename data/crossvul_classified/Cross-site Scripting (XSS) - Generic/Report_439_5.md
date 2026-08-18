# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 439_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `439_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-24 of the vulnerable file.

/*!
* Simditor v2.3.21
* http://simditor.tower.im/
* 2018-10-17
*/
(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module unless amdModuleId is set
    define('simditor', ["jquery","simple-module","simple-hotkeys","simple-uploader"], function ($, SimpleModule, simpleHotkeys, simpleUploader) {
      return (root['Simditor'] = factory($, SimpleModule, simpleHotkeys, simpleUploader));
    });
  } else if (typeof exports === 'object') {
    // Node. Does not work with strict CommonJS, but
    // only CommonJS-like environments that support module.exports,
    // like Node.
    module.exports = factory(require("jquery"),require("simple-module"),require("simple-hotkeys"),require("simple-uploader"));
  } else {
    root['Simditor'] = factory(jQuery,SimpleModule,simple.hotkeys,simple.uploader);
  }
}(this, function ($, SimpleModule, simpleHotkeys, simpleUploader) {

var AlignmentButton, BlockquoteButton, BoldButton, Button, Clipboard, CodeButton, CodePopover, ColorButton, FontScaleButton, Formatter, HrButton, ImageButton, ImagePopover, IndentButton, Indentation, InputManager, ItalicButton, Keystroke, LinkButton, LinkPopover, ListButton, OrderListButton, OutdentButton, Popover, Selection, Simditor, StrikethroughButton, TableButton, TitleButton, Toolbar, UnderlineButton, UndoManager, UnorderListButton, Util,
  extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
  hasProp = {}.hasOwnProperty,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,23 +1,23 @@
 /*!
 * Simditor v2.3.21
 * http://simditor.tower.im/
-* 2018-10-17
+* 2018-11-09
 */
 (function (root, factory) {
   if (typeof define === 'function' && define.amd) {
     // AMD. Register as an anonymous module unless amdModuleId is set
-    define('simditor', ["jquery","simple-module","simple-hotkeys","simple-uploader"], function ($, SimpleModule, simpleHotkeys, simpleUploader) {
-      return (root['Simditor'] = factory($, SimpleModule, simpleHotkeys, simpleUploader));
+    define('simditor', ["jquery","simple-module","simple-hotkeys","simple-uploader","dompurify"], function ($, SimpleModule, simpleHotkeys, simpleUploader, DOMPurify) {
+      return (root['Simditor'] = factory($, SimpleModule, simpleHotkeys, simpleUploader, DOMPurify));
     });
   } else if (typeof exports === 'object') {
     // Node. Does not work with strict CommonJS, but
     // only CommonJS-like environments that support module.exports,
     // like Node.
-    module.exports = factory(require("jquery"),require("simple-module"),require("simple-hotkeys"),require("simple-uploader"));
+    module.exports = factory(require("jquery"),require("simple-module"),require("simple-hotkeys"),require("simple-uploader"),require("dompurify"));
   } else {
-    root['Simditor'] = factory(jQuery,SimpleModule,simple.hotkeys,simple.uploader);
+    root['Simditor'] = factory(jQuery,SimpleModule,simple.hotkeys,simple.uploader,window.DOMPurify);
   }
-}(this, function ($, SimpleModule, simpleHotkeys, simpleUploader) {
+}(this, function ($, SimpleModule, simpleHotkeys, simpleUploader, DOMPurify) {
 
 var AlignmentButton, BlockquoteButton, BoldButton, Button, Clipboard, CodeButton, CodePopover, ColorButton, FontScaleButton, Formatter, HrButton, ImageButton, ImagePopover, IndentButton, Indentation, InputManager, ItalicButton, Keystroke, LinkButton, LinkPopover, ListButton, OrderListButton, OutdentButton, Popover, Selection, Simditor, StrikethroughButton, TableButton, TitleButton, Toolbar, UnderlineButton, UndoManager, UnorderListButton, Util,
   extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
@@ -2342,7 +2342,7 @@
       return function() {
         var pasteContent;
         _this.editor.hidePopover();
-        _this.editor.body.get(0).innerHTML = state.html;
+        _this.editor.body.get(0).innerHTML = DOMPurify ? DOMPurify.sanitize(state.html) : state.html;
         _this.editor.undoManager.caretPosition(state.caret);
         _this.editor.body.focus();
         _this.editor.selection.reset();
@@ -2649,7 +2649,7 @@
   Simditor.prototype.setValue = function(val) {
     this.hidePopover();
     this.textarea.val(val);
-    this.body.get(0).innerHTML = val;
+    this.body.get(0).innerHTML = DOMPurify ? DOMPurify.sanitize(val) : val;
     this.formatter.format();
     this.formatter.decorate();
     this.util.reflow(this.body);
```
