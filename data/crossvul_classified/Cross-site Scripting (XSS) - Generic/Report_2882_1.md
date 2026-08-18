# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2882_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2882_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 12-52 of the vulnerable file.

 * @license   http://www.mozilla.org/MPL/2.0/ Mozilla Public License Version 2.0
 * @link      http://www.phpmyfaq.de
 * @since     2014-08-16
 */

/*global $:false */

$(document).ready(function () {
    'use strict';

    $('.btn-edit').on('click', function () {
        var id = $(this).data('btn-id');
        var span = $('span[data-tag-id="' + id + '"]');

        if (span.length > 0) {
            span.replaceWith(
                '<input name="tag" class="form-control" data-tag-id="' + id + '" value="' + span.html() + '">'
            );
        } else {
            var input = $('input[data-tag-id="' + id + '"]');
            input.replaceWith('<span data-tag-id="' + id + '">' + input.val() + '</span>');
        }
    });

    $('.tag-form').bind('submit', function (event) {

        event.preventDefault();

        var input = $('input[data-tag-id]:focus');
        var id = input.data('tag-id');
        var tag = input.val();

        $.ajax({
            url: 'index.php?action=ajax&ajax=tags&ajaxaction=update',
            type: 'POST',
            data: 'id=' + id + '&tag=' + tag,
            dataType: 'json',
            beforeSend: function () {
                $('#saving_data_indicator').html(
                    '<i aria-hidden="true" class="fa fa-spinner fa-spin"></i> Saving ...'
                );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,7 +29,7 @@
             );
         } else {
             var input = $('input[data-tag-id="' + id + '"]');
-            input.replaceWith('<span data-tag-id="' + id + '">' + input.val() + '</span>');
+            input.replaceWith('<span data-tag-id="' + id + '">' + input.val().replace(/\//g, '&#x2F;') + '</span>');
         }
     });
 
@@ -40,11 +40,12 @@
         var input = $('input[data-tag-id]:focus');
         var id = input.data('tag-id');
         var tag = input.val();
+        var csrf = $('input[name=csrf]').val();
 
         $.ajax({
             url: 'index.php?action=ajax&ajax=tags&ajaxaction=update',
             type: 'POST',
-            data: 'id=' + id + '&tag=' + tag,
+            data: 'id=' + id + '&tag=' + tag + '&csrf=' + csrf,
             dataType: 'json',
             beforeSend: function () {
                 $('#saving_data_indicator').html(
@@ -52,9 +53,9 @@
                 );
             },
             success: function (message) {
-                input.replaceWith('<span data-tag-id="' + id + '">' + input.val() + '</span>');
-                $('span[data-tag-id="' + id + '"]').append(' ✓');
-                $('#saving_data_indicator').html('✓ ' + message);
+                input.replaceWith('<span data-tag-id="' + id + '">' + input.val().replace(/\//g, '&#x2F;') + '</span>');
+                $('span[data-tag-id="' + id + '"]');
+                $('#saving_data_indicator').html(message);
             }
         });
 
```
