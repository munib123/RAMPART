# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in javascript
**Pair ID:** 3090_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3090_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```javascript
Lines 40-80 of the vulnerable file.

                // create jQuery object from button instance.
                var $readmore = button.render();
                return $readmore;
            });

        },
        'elfinder': function (context) {
            var self = this;
            
            // ui has renders to build ui elements.
            //  - you can create a button with `ui.button`
            var ui = $.summernote.ui;
            
            // add elfinder button
            context.memo('button.elfinder', function () {
                // create button
                var button = ui.button({
                    contents: '<i class="fa fa-list-alt"/> File Manager',
                    tooltip: 'elfinder',
                    click: function () {
                        elfinderDialog();
                    }
                });
                
                // create jQuery object from button instance.
                var $elfinder = button.render();
                return $elfinder;
            });
            

        },
        'gxcode': function (context) {
            var self = this;
            
            // ui has renders to build ui elements.
            //  - you can create a button with `ui.button`
            var ui = $.summernote.ui;
            
            // add elfinder button
            context.memo('button.gxcode', function () {
                // create button
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,7 +57,7 @@
                     contents: '<i class="fa fa-list-alt"/> File Manager',
                     tooltip: 'elfinder',
                     click: function () {
-                        elfinderDialog();
+                        elfinderDialog($(this).closest('.note-editor').parent().children('.summernote'));
                     }
                 });
                 
```
