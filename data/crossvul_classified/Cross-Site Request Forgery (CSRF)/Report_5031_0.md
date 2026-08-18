# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in javascript
**Pair ID:** 5031_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5031_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```javascript
Lines 140-180 of the vulnerable file.

    var keys = this.keys_list.get_selection();

    if (!keys.length || !confirm(this.get_label('enigma.keyremoveconfirm')))
        return;

    var lock = this.display_message(this.get_label('enigma.keyremoving'), 'loading'),
        post = {_a: 'delete', _keys: keys};

    // send request to server
    this.http_post('plugin.enigmakeys', post, lock);
};

// Export key(s)
rcube_webmail.prototype.enigma_export = function(selected)
{
    var keys = selected ? this.keys_list.get_selection().join(',') : '*';

    if (!keys.length)
        return;

    this.goto_url('plugin.enigmakeys', {_a: 'export', _keys: keys});
};

// Submit key(s) import form
rcube_webmail.prototype.enigma_import = function()
{
    var form, file;

    if (form = this.gui_objects.importform) {
        file = document.getElementById('rcmimportfile');
        if (file && !file.value) {
            alert(this.get_label('selectimportfile'));
            return;
        }

        var lock = this.set_busy(true, 'importwait');

        form.action = this.add_url(form.action, '_unlock', lock);
        form.submit();

        this.lock_form(form, true);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -157,7 +157,7 @@
     if (!keys.length)
         return;
 
-    this.goto_url('plugin.enigmakeys', {_a: 'export', _keys: keys});
+    this.goto_url('plugin.enigmakeys', {_a: 'export', _keys: keys}, false, true);
 };
 
 // Submit key(s) import form
```
