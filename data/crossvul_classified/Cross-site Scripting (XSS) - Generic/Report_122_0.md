# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 122_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `122_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-37 of the vulnerable file.

/* global Whisper: false */
/* global i18n: false */
/* global textsecure: false */
/* global _: false */
/* global emoji_util: false */
/* global Mustache: false */
/* global $: false */

// eslint-disable-next-line func-names
(function() {
  'use strict';

  const { Signal } = window;
  const { loadAttachmentData } = window.Signal.Migrations;

  window.Whisper = window.Whisper || {};

  const ErrorIconView = Whisper.View.extend({
    templateName: 'error-icon',
    className: 'error-icon-container',
    initialize() {
      if (this.model.name === 'UnregisteredUserError') {
        this.$el.addClass('unregistered-user-error');
      }
    },
  });
  const NetworkErrorView = Whisper.View.extend({
    tagName: 'span',
    className: 'hasRetry',
    templateName: 'hasRetry',
    render_attributes() {
      let messageNotSent;

      if (!this.model.someRecipientsFailed()) {
        messageNotSent = i18n('messageNotSent');
      }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,6 +14,8 @@
   const { loadAttachmentData } = window.Signal.Migrations;
 
   window.Whisper = window.Whisper || {};
+
+  const URL_REGEX = /(^|[\s\n]|<br\/?>)((?:https?|ftp):\/\/[-A-Z0-9\u00A0-\uD7FF\uE000-\uFDCF\uFDF0-\uFFFD+\u0026\u2019@#/%?=()~_|!:,.;]*[-A-Z0-9+\u0026@#/%=~()_|])/gi;
 
   const ErrorIconView = Whisper.View.extend({
     templateName: 'error-icon',
@@ -508,7 +510,11 @@
 
       if (body.length > 0) {
         const escapedBody = body.html();
-        body.html(Signal.HTML.render(escapedBody));
+        body.html(
+          escapedBody
+            .replace(/\n/g, '<br>')
+            .replace(URL_REGEX, "$1<a href='$2' target='_blank'>$2</a>")
+        );
       }
 
       this.renderSent();
```
