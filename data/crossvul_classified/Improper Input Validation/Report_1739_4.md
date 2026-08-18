# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 1739_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1739_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 515-555 of the vulnerable file.

            $('.dynamic-instructions').hide();
        } else {
            $('.dynamic-instructions').show();
        }
    };

    NotebookList.prototype.add_link = function (model, item) {
        var path = model.path,
            name = model.name;
        var running = (model.type == 'notebook' && this.sessions[path] !== undefined);
        
        item.data('name', name);
        item.data('path', path);
        item.data('type', model.type);
        item.find(".item_name").text(name);
        var icon = NotebookList.icons[model.type];
        if (running) {
            icon = 'running_' + icon;
        }
        var uri_prefix = NotebookList.uri_prefixes[model.type];
        item.find(".item_icon").addClass(icon).addClass('icon-fixed-width');
        var link = item.find("a.item_link")
            .attr('href',
                utils.url_join_encode(
                    this.base_url,
                    uri_prefix,
                    path
                )
            );

        item.find(".item_buttons .running-indicator").css('visibility', running ? '' : 'hidden');

        // directory nav doesn't open new tabs
        // files, notebooks do
        if (model.type !== "directory") {
            link.attr('target',IPython._target);
        }
    };


    NotebookList.prototype.add_name_input = function (name, item, icon_type) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -532,6 +532,13 @@
             icon = 'running_' + icon;
         }
         var uri_prefix = NotebookList.uri_prefixes[model.type];
+        if (model.type === 'file' &&
+            model.mimetype && model.mimetype.substr(0,5) !== 'text/'
+        ) {
+            // send text/unidentified files to editor, others go to raw viewer
+            uri_prefix = 'files';
+        }
+        
         item.find(".item_icon").addClass(icon).addClass('icon-fixed-width');
         var link = item.find("a.item_link")
             .attr('href',
```
