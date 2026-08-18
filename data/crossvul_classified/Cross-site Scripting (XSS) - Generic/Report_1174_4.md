# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1174_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1174_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 118-158 of the vulnerable file.

                if (textStatus === 'success') {
                    this.handleDeleteItemResponse(response, $row);
                }
            }, this));
        },

        handleDeleteItemResponse: function(response, $row) {
            var id = this.getItemId($row),
                name = this.getItemName($row);

            if (response.success) {
                if (this.sorter) {
                    this.sorter.removeItems($row);
                }

                $row.remove();
                this.totalItems--;
                this.updateUI();
                this.onDeleteItem(id);

                Craft.cp.displayNotice(Craft.t('app', this.settings.deleteSuccessMessage, {name: Craft.escapeHtml(name)}));
            }
            else {
                Craft.cp.displayError(Craft.t('app', this.settings.deleteFailMessage, {name: Craft.escapeHtml(name)}));
            }
        },

        onReorderItems: function(ids) {
            this.settings.onReorderItems(ids);
        },

        onDeleteItem: function(id) {
            this.settings.onDeleteItem(id);
        },

        getItemId: function($row) {
            return $row.attr(this.settings.idAttribute);
        },

        getItemName: function($row) {
            return $row.attr(this.settings.nameAttribute);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -135,10 +135,10 @@
                 this.updateUI();
                 this.onDeleteItem(id);
 
-                Craft.cp.displayNotice(Craft.t('app', this.settings.deleteSuccessMessage, {name: Craft.escapeHtml(name)}));
+                Craft.cp.displayNotice(Craft.t('app', this.settings.deleteSuccessMessage, {name: name}));
             }
             else {
-                Craft.cp.displayError(Craft.t('app', this.settings.deleteFailMessage, {name: Craft.escapeHtml(name)}));
+                Craft.cp.displayError(Craft.t('app', this.settings.deleteFailMessage, {name: name}));
             }
         },
 
@@ -155,7 +155,7 @@
         },
 
         getItemName: function($row) {
-            return $row.attr(this.settings.nameAttribute);
+            return Craft.escapeHtml($row.attr(this.settings.nameAttribute));
         },
 
         updateUI: function() {
```
