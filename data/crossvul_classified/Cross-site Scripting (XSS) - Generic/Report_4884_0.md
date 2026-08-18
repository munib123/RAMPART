# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4884_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4884_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 243-283 of the vulnerable file.

    function formatDatalist (datalist) {
        var loading_markup = '<i class="fa fa-spinner fa-spin" aria-hidden="true"></i> Loading...';
        if (datalist.loading) {
            return loading_markup;
        }

        var markup = "<div class='clearfix'>" ;
        markup +="<div class='pull-left' style='padding-right: 10px;'>";
        if (datalist.image) {
            markup += "<div style='width: 30px;'><img src='" + datalist.image + "' style='max-height: 20px; max-width: 30px;'></div>";
        } else {
            markup += "<div style='height: 20px; width: 30px;'></div>";
        }

        markup += "</div><div>" + datalist.text + "</div>";
        markup += "</div>";
        return markup;
    }

    function formatDataSelection (datalist) {
        return datalist.text;
    }

    // This handles the radio button selectors for the checkout-to-foo options
    // on asset checkout and also on asset edit
    $(function() {
        $('input[name=checkout_to_type]').on("change",function () {
            var assignto_type = $('input[name=checkout_to_type]:checked').val();
            var userid = $('#assigned_user option:selected').val();

            if (assignto_type == 'asset') {
                $('#current_assets_box').fadeOut();
                $('#assigned_asset').show();
                $('#assigned_user').hide();
                $('#assigned_location').hide();
                $('.notification-callout').fadeOut();

            } else if (assignto_type == 'location') {
                $('#current_assets_box').fadeOut();
                $('#assigned_asset').hide();
                $('#assigned_user').hide();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -260,7 +260,18 @@
     }
 
     function formatDataSelection (datalist) {
-        return datalist.text;
+        // This a heinous workaround for a known bug in Select2.
+        // Without this, the rich selectlists are vulnerable to XSS.
+        // Many thanks to @uberbrady for this fix. It ain't pretty,
+        // but it resolves the issue until Select2 addresses it on their end.
+        //
+        // Bug was reported in 2016 :{
+        // https://github.com/select2/select2/issues/4587
+
+        return datalist.text.replace(/>/g, '&gt;')
+            .replace(/</g, '&lt;')
+            .replace(/"/g, '&quot;')
+            .replace(/'/g, '&#039;');
     }
 
     // This handles the radio button selectors for the checkout-to-foo options
```
