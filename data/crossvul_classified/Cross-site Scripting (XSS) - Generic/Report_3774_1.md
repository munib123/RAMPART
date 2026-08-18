# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3774_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3774_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 3281-3322 of the vulnerable file.


    if (save)
      this.cmp_hash = str;

    return str;
  };

  this.change_identity = function(obj, show_sig)
  {
    if (!obj || !obj.options)
      return false;

    if (!show_sig)
      show_sig = this.env.show_sig;

    var cursor_pos, p = -1,
      id = obj.options[obj.selectedIndex].value,
      input_message = $("[name='_message']"),
      message = input_message.val(),
      is_html = ($("input[name='_is_html']").val() == '1'),
      sig = this.env.identity,
      sig_separator = this.env.sig_above && (this.env.compose_mode == 'reply' || this.env.compose_mode == 'forward') ? '---' : '-- ';

    // enable manual signature insert
    if (this.env.signatures && this.env.signatures[id]) {
      this.enable_command('insert-sig', true);
      this.env.compose_commands.push('insert-sig');
    }
    else
      this.enable_command('insert-sig', false);

    if (!is_html) {
      // remove the 'old' signature
      if (show_sig && sig && this.env.signatures && this.env.signatures[sig]) {

        sig = this.env.signatures[sig].is_html ? this.env.signatures[sig].plain_text : this.env.signatures[sig].text;
        sig = sig.replace(/\r\n/g, '\n');

        if (!sig.match(/^--[ -]\n/m))
          sig = sig_separator + '\n' + sig;

        p = this.env.sig_above ? message.indexOf(sig) : message.lastIndexOf(sig);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3298,8 +3298,7 @@
       input_message = $("[name='_message']"),
       message = input_message.val(),
       is_html = ($("input[name='_is_html']").val() == '1'),
-      sig = this.env.identity,
-      sig_separator = this.env.sig_above && (this.env.compose_mode == 'reply' || this.env.compose_mode == 'forward') ? '---' : '-- ';
+      sig = this.env.identity;
 
     // enable manual signature insert
     if (this.env.signatures && this.env.signatures[id]) {
@@ -3312,12 +3311,8 @@
     if (!is_html) {
       // remove the 'old' signature
       if (show_sig && sig && this.env.signatures && this.env.signatures[sig]) {
-
-        sig = this.env.signatures[sig].is_html ? this.env.signatures[sig].plain_text : this.env.signatures[sig].text;
+        sig = this.env.signatures[sig].text;
         sig = sig.replace(/\r\n/g, '\n');
-
-        if (!sig.match(/^--[ -]\n/m))
-          sig = sig_separator + '\n' + sig;
 
         p = this.env.sig_above ? message.indexOf(sig) : message.lastIndexOf(sig);
         if (p >= 0)
@@ -3325,11 +3320,8 @@
       }
       // add the new signature string
       if (show_sig && this.env.signatures && this.env.signatures[id]) {
-        sig = this.env.signatures[id]['is_html'] ? this.env.signatures[id]['plain_text'] : this.env.signatures[id]['text'];
+        sig = this.env.signatures[id].text;
         sig = sig.replace(/\r\n/g, '\n');
-
-        if (!sig.match(/^--[ -]\n/m))
-          sig = sig_separator + '\n' + sig;
 
         if (this.env.sig_above) {
           if (p >= 0) { // in place of removed signature
@@ -3394,21 +3386,8 @@
         }
       }
 
-      if (this.env.signatures[id]) {
-        if (this.env.signatures[id].is_html) {
-          sig = this.env.signatures[id].text;
-          if (!this.env.signatures[id].plain_text.match(/^--[ -]\r?\n/m))
-            sig = sig_separator + '<br />' + sig;
-        }
-        else {
-          sig = this.env.signatures[id].text;
-          if (!sig.match(/^--[ -]\r?\n/m))
-            sig = sig_separator + '\n' + sig;
-          sig = '<pre>' + sig + '</pre>';
-        }
-
-        sigElem.innerHTML = sig;
-      }
+      if (this.env.signatures[id])
+        sigElem.innerHTML = this.env.signatures[id].html;
     }
 
     this.env.identity = id;
```
