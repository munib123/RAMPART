# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in javascript
**Pair ID:** 5032_6
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5032_6`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```javascript
Lines 982-1022 of the vulnerable file.

          break;
        }

      case 'load-images':
        if (this.env.uid)
          this.show_message(this.env.uid, true, this.env.action=='preview');
        break;

      case 'load-attachment':
      case 'open-attachment':
      case 'download-attachment':
        var qstring = '_mbox='+urlencode(this.env.mailbox)+'&_uid='+this.env.uid+'&_part='+props,
          mimetype = this.env.attachments[props];

        // open attachment in frame if it's of a supported mimetype
        if (command != 'download-attachment' && mimetype && this.env.mimetypes && $.inArray(mimetype, this.env.mimetypes) >= 0) {
          if (this.open_window(this.env.comm_path+'&_action=get&'+qstring+'&_frame=1'))
            break;
        }

        this.goto_url('get', qstring+'&_download=1', false);
        break;

      case 'select-all':
        this.select_all_mode = props ? false : true;
        this.dummy_select = true; // prevent msg opening if there's only one msg on the list
        if (props == 'invert')
          this.message_list.invert_selection();
        else
          this.message_list.select_all(props == 'page' ? '' : props);
        this.dummy_select = null;
        break;

      case 'select-none':
        this.select_all_mode = false;
        this.message_list.clear_selection();
        break;

      case 'expand-all':
        this.env.autoexpand_threads = 1;
        this.message_list.expand_all();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -999,7 +999,7 @@
             break;
         }
 
-        this.goto_url('get', qstring+'&_download=1', false);
+        this.goto_url('get', qstring+'&_download=1', false, true);
         break;
 
       case 'select-all':
@@ -1205,10 +1205,10 @@
 
       case 'download':
         if (this.env.action == 'get') {
-          location.href = location.href.replace(/_frame=/, '_download=');
+          location.href = this.secure_url(location.href.replace(/_frame=/, '_download='));
         }
         else if (uid = this.get_single_uid()) {
-          this.goto_url('viewsource', this.params_from_uid(uid, {_save: 1}));
+          this.goto_url('viewsource', this.params_from_uid(uid, {_save: 1}), false, true);
         }
         break;
 
@@ -1296,13 +1296,13 @@
 
       case 'export':
         if (this.contact_list.rowcount > 0) {
-          this.goto_url('export', { _source: this.env.source, _gid: this.env.group, _search: this.env.search_request });
+          this.goto_url('export', { _source: this.env.source, _gid: this.env.group, _search: this.env.search_request }, false, true);
         }
         break;
 
       case 'export-selected':
         if (this.contact_list.rowcount > 0) {
-          this.goto_url('export', { _source: this.env.source, _gid: this.env.group, _cid: this.contact_list.get_selection().join(',') });
+          this.goto_url('export', { _source: this.env.source, _gid: this.env.group, _cid: this.contact_list.get_selection().join(',') }, false, true);
         }
         break;
 
@@ -1417,7 +1417,7 @@
     if (task == 'mail')
       url += '&_mbox=INBOX';
     else if (task == 'logout' && !this.env.server_error) {
-      url += '&_token=' + this.env.request_token;
+      url = this.secure_url(url);
       this.clear_compose_data();
     }
 
@@ -1465,6 +1465,12 @@
 
     return url + '?' + name + '=' + value;
   };
+
+  // append CSRF protection token to the given url
+  this.secure_url = function(url)
+  {
+    return this.add_url(url, '_token', this.env.request_token);
+  },
 
   this.is_framed = function()
   {
@@ -7282,9 +7288,11 @@
     }
   };
 
-  this.goto_url = function(action, query, lock)
-  {
-    this.redirect(this.url(action, query), lock);
+  this.goto_url = function(action, query, lock, secure)
+  {
+    var url = this.url(action, query)
+    if (secure) url = this.secure_url(url);
+    this.redirect(url, lock);
   };
 
   this.location_href = function(url, target, frame)
```
