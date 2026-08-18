# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 448_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `448_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 366-417 of the vulnerable file.

    };


    NotebookList.prototype.sessions_loaded = function(data){
        this.sessions = data;
        this.load_list();
    };

    NotebookList.prototype.load_list = function () {
        var that = this;
        // Add an event handler browser back and forward events
        window.onpopstate = function(e) {
            var path = (window.history.state && window.history.state.path) ?
                    window.history.state.path : that.initial_notebook_path;
            that.update_location(path);
        };
        var breadcrumb = $('.breadcrumb');
        breadcrumb.empty();
        var list_item = $('<li/>');
        var root_url = utils.url_path_join(that.base_url, '/tree');
        var root = $('<li/>').append('<a href="' + root_url + '"><i class="fa fa-folder"></i></a>').click(function(e) {
            // Allow the default browser action when the user holds a modifier (e.g., Ctrl-Click)
            if(e.altKey || e.metaKey || e.shiftKey) {
                return true;
            }
            var path = '';
            window.history.pushState({
                path: path
            }, 'Home', utils.url_path_join(that.base_url, 'tree'));
            that.update_location(path);
            return false;
        });
        breadcrumb.append(root);
        var path_parts = [];
        this.notebook_path.split('/').forEach(function(path_part) {
            path_parts.push(path_part);
            var path = path_parts.join('/');
            var url = utils.url_path_join(
                that.base_url,
                '/tree',
                utils.encode_uri_components(path)
            );
            var crumb = $('<li/>').append('<a href="' + url + '">' + path_part + '</a>').click(function(e) {
                // Allow the default browser action when the user holds a modifier (e.g., Ctrl-Click)
                if(e.altKey || e.metaKey || e.shiftKey) {
                    return true;
                }
                window.history.pushState({
                    path: path
                }, path, url);
                that.update_location(path);
                return false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -383,18 +383,28 @@
         breadcrumb.empty();
         var list_item = $('<li/>');
         var root_url = utils.url_path_join(that.base_url, '/tree');
-        var root = $('<li/>').append('<a href="' + root_url + '"><i class="fa fa-folder"></i></a>').click(function(e) {
-            // Allow the default browser action when the user holds a modifier (e.g., Ctrl-Click)
-            if(e.altKey || e.metaKey || e.shiftKey) {
-                return true;
-            }
-            var path = '';
-            window.history.pushState({
-                path: path
-            }, 'Home', utils.url_path_join(that.base_url, 'tree'));
-            that.update_location(path);
-            return false;
-        });
+        var root = $('<li/>').append(
+            $("<a/>")
+            .attr('href', root_url)
+            .append(
+                $("<i/>")
+                .addClass('fa fa-folder')
+            )
+            .click(function(e) {
+                // Allow the default browser action when the user holds a modifier (e.g., Ctrl-Click)
+                if(e.altKey || e.metaKey || e.shiftKey) {
+                    return true;
+                }
+                var path = '';
+                window.history.pushState(
+                    {path: path},
+                    'Home',
+                    utils.url_path_join(that.base_url, 'tree')
+                );
+                that.update_location(path);
+                return false;
+            })
+        );
         breadcrumb.append(root);
         var path_parts = [];
         this.notebook_path.split('/').forEach(function(path_part) {
@@ -405,17 +415,24 @@
                 '/tree',
                 utils.encode_uri_components(path)
             );
-            var crumb = $('<li/>').append('<a href="' + url + '">' + path_part + '</a>').click(function(e) {
-                // Allow the default browser action when the user holds a modifier (e.g., Ctrl-Click)
-                if(e.altKey || e.metaKey || e.shiftKey) {
-                    return true;
-                }
-                window.history.pushState({
-                    path: path
-                }, path, url);
-                that.update_location(path);
-                return false;
-            });
+            var crumb = $('<li/>').append(
+                $('<a/>')
+                .attr('href', url)
+                .text(path_part)
+                .click(function(e) {
+                    // Allow the default browser action when the user holds a modifier (e.g., Ctrl-Click)
+                    if(e.altKey || e.metaKey || e.shiftKey) {
+                        return true;
+                    }
+                    window.history.pushState(
+                        {path: path},
+                        path,
+                        url
+                    );
+                    that.update_location(path);
+                    return false;
+                })
+            );
             breadcrumb.append(crumb);
         });
         this.contents.list_contents(that.notebook_path).then(
```
