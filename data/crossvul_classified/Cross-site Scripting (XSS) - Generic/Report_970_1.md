# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 970_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `970_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 89-129 of the vulnerable file.

            list.push('accountId');
            return list;
        },

        getValueForDisplay: function () {
            if (this.mode == 'detail') {
                var address = this.model.get(this.name);
                return this.getDetailAddressHtml(address);
            }
            return Dep.prototype.getValueForDisplay.call(this);
        },

        getDetailAddressHtml: function (address) {
            if (!address) {
                return '';
            }

            var fromString = this.model.get('fromString') || this.model.get('fromName');

            var name = this.nameHash[address] || this.parseNameFromStringAddress(fromString) || null;
            var entityType = this.typeHash[address] || null;
            var id = this.idHash[address] || null;

            var addressHtml = '<span>' + address + '</span>';

            var lineHtml = '';
            if (id) {
                lineHtml = '<div>' + '<a href="#' + entityType + '/view/' + id + '">' + name + '</a> <span class="text-muted">&#187;</span> ' + addressHtml + '</div>';
            } else {
                if (this.getAcl().check('Contact', 'create') || this.getAcl().check('Lead', 'create')) {
                    lineHtml += this.getCreateHtml(address);
                }
                if (name) {
                    lineHtml += '<span>' + name + ' <span class="text-muted">&#187;</span> ' + addressHtml + '</span>';
                } else {
                    lineHtml += addressHtml;
                }
            }
            lineHtml = '<div>' + lineHtml + '</div>';
            return lineHtml;
        },
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -106,6 +106,11 @@
             var fromString = this.model.get('fromString') || this.model.get('fromName');
 
             var name = this.nameHash[address] || this.parseNameFromStringAddress(fromString) || null;
+
+            if (name) {
+                name = this.getHelper().escapeString(name);
+            }
+
             var entityType = this.typeHash[address] || null;
             var id = this.idHash[address] || null;
 
@@ -129,6 +134,8 @@
         },
 
         getCreateHtml: function (address) {
+            address = this.getHelper().escapeString(address);
+
             var html = '<span class="dropdown email-address-create-dropdown pull-right">' +
                 '<button class="dropdown-toggle btn btn-link btn-sm" data-toggle="dropdown">' +
                     '<span class="caret text-muted"></span>' +
@@ -177,6 +184,10 @@
                 if (this.name == 'from') {
                     name = this.parseNameFromStringAddress(fromString) || null;
                 }
+            }
+
+            if (name) {
+                name = this.getHelper().escapeString(name);
             }
 
             var attributes = {
@@ -238,6 +249,10 @@
                 if (this.name == 'from') {
                     name = this.parseNameFromStringAddress(fromString) || null;
                 }
+            }
+
+            if (name) {
+                name = this.getHelper().escapeString(name);
             }
 
             var attributes = {
```
