# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 970_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `970_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 186-226 of the vulnerable file.

                });

                this.once('render', function () {
                    this.$input.autocomplete('dispose');
                }, this);

                this.once('remove', function () {
                    this.$input.autocomplete('dispose');
                }, this);
            }
        },

        checkEmailAddressInString: function (string) {
            var arr = string.match(this.emailAddressRegExp);
            if (!arr || !arr.length) return;

            return true;
        },

        addAddress: function (address, name, type, id) {
            if (this.justAddedAddress) {
                this.deleteAddress(this.justAddedAddress);
            }
            this.justAddedAddress = address;
            setTimeout(function () {
                this.justAddedAddress = null;
            }.bind(this), 100);

            address = address.trim();

            if (!type) {
                var arr = address.match(this.emailAddressRegExp);
                if (!arr || !arr.length) return;
                address = arr[0];
            }

            if (!~this.addressList.indexOf(address)) {
                this.addressList.push(address);
                this.nameHash[address] = name;

                if (type) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -203,6 +203,10 @@
         },
 
         addAddress: function (address, name, type, id) {
+            if (name) {
+                name = this.getHelper().escapeString(name);
+            }
+
             if (this.justAddedAddress) {
                 this.deleteAddress(this.justAddedAddress);
             }
@@ -236,6 +240,13 @@
         },
 
         addAddressHtml: function (address, name) {
+            if (name) {
+                name = this.getHelper().escapeString(name);
+            }
+            if (address) {
+                name = this.getHelper().escapeString(address);
+            }
+
             var conteiner = this.$el.find('.link-container');
             var html =
             '<div data-address="'+address+'" class="list-group-item">' +
@@ -287,6 +298,10 @@
             var id = this.idHash[address] || null;
 
             var addressHtml = '<span>' + address + '</span>';
+
+            if (name) {
+                name = this.getHelper().escapeString(name);
+            }
 
             var lineHtml;
             if (id) {
```
