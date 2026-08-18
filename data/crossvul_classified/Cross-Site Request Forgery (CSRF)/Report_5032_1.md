# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in javascript
**Pair ID:** 5032_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5032_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```javascript
Lines 164-204 of the vulnerable file.

{
  for (var i in this.env.filtersets)
    if (this.env.filtersets[i] == name)
      return i;
};

// Filters listing request
rcube_webmail.prototype.managesieve_list = function(script)
{
  var lock = this.set_busy(true, 'loading');

  this.http_post('plugin.managesieve-action', '_act=list&_set='+urlencode(script), lock);
};

// Script download request
rcube_webmail.prototype.managesieve_setget = function()
{
  var id = this.filtersets_list.get_single_selection(),
    script = this.env.filtersets[id];

  location.href = this.env.comm_path+'&_action=plugin.managesieve-action&_act=setget&_set='+urlencode(script);
};

// Set activate/deactivate request
rcube_webmail.prototype.managesieve_setact = function()
{
  var id = this.filtersets_list.get_single_selection(),
   lock = this.set_busy(true, 'loading'),
    script = this.env.filtersets[id],
    action = $('#rcmrow'+id).hasClass('disabled') ? 'setact' : 'deact';

  this.http_post('plugin.managesieve-action', '_act='+action+'&_set='+urlencode(script), lock);
};

// Set delete request
rcube_webmail.prototype.managesieve_setdel = function()
{
  if (!confirm(this.get_label('managesieve.setdeleteconfirm')))
    return false;

  var id = this.filtersets_list.get_single_selection(),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -181,7 +181,7 @@
   var id = this.filtersets_list.get_single_selection(),
     script = this.env.filtersets[id];
 
-  location.href = this.env.comm_path+'&_action=plugin.managesieve-action&_act=setget&_set='+urlencode(script);
+  this.goto_url('plugin.managesieve-action', {_act: 'setget', _set: script}, false, true);
 };
 
 // Set activate/deactivate request
```
