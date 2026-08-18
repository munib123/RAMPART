# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 5657_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5657_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 335-375 of the vulnerable file.

 * format expected by jQuery.ui.autocomplete. It also adds some additional
 * explanatory text to the bottom of the autocomplete list.
 *
 * options has the following fields:
 *
 *    fieldName   - The field name ("groups" or "people").
 *    nameKey     - The key containing the name in the result data.
 *    descKey     - The key containing the description in the result
 *                  data. This is optional.
 *    extraParams - Extra parameters to send in the query. This is optional.
 *
 * @param {object} options    The options, as listed above.
 *
 * @return {jQuery} This jQuery set.
 */
$.fn.reviewsAutoComplete = function(options) {
    return this.each(function() {
        $(this)
            .autocomplete({
                formatItem: function(data) {
                    var s = data[options.nameKey];

                    if (options.descKey) {
                        s += " <span>(" + data[options.descKey] + ")</span>";
                    }

                    return s;
                },
                matchCase: false,
                multiple: true,
                parse: function(data) {
                    var jsonData = eval("(" + data + ")");
                    var items = jsonData[options.fieldName];
                    var parsed = [];

                    for (var i = 0; i < items.length; i++) {
                        var value = items[i];

                        parsed.push({
                            data: value,
                            value: value[options.nameKey],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -352,10 +352,12 @@
         $(this)
             .autocomplete({
                 formatItem: function(data) {
-                    var s = data[options.nameKey];
+                    var s = data[options.nameKey],
+                        desc;
 
                     if (options.descKey) {
-                        s += " <span>(" + data[options.descKey] + ")</span>";
+                        desc = $('<div/>').text(data[options.descKey]).html();
+                        s += " <span>(" + desc + ")</span>";
                     }
 
                     return s;
```
