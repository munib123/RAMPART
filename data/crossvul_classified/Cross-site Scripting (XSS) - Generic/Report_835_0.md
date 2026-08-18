# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 835_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `835_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 80-120 of the vulnerable file.

    simplePopup("/event_delegations/delegateEvent/" + id);
}

function genericPopup(url, popupTarget, callback) {
    $.get(url, function(data) {
        $(popupTarget).html(data);
        $(popupTarget).fadeIn();
        left = ($(window).width() / 2) - ($(popupTarget).width() / 2);
        $(popupTarget).css({'left': left + 'px'});
        $("#gray_out").fadeIn();
        if (callback !== undefined) {
            callback();
        }
    });
}

function screenshotPopup(url, title) {
    if (!url.startsWith('data:image/')) {
        url = url.slice(0, -1);
    }
    popupHtml = '<it class="fa fa-spin fa-spinner" style="font-size: xx-large; color: white; position: fixed; left: 50%; top: 50%;"></it>'
    popupHtml += '<img class="screenshot_box-content hidden" src="' + url + '" id="screenshot-image" title="' + title + '" alt="' + title + '" onload="$(this).show(); $(this).parent().find(\'.fa-spinner\').remove();"/>';
    popupHtml += '<div class="close-icon useCursorPointer" onClick="closeScreenshot();"></div>';
    if (!url.startsWith('data:image/')) {
        popupHtml += '<a class="close-icon useCursorPointer fa fa-expand" style="right: 20px; background: black; color: white; text-decoration: none;" target="_blank" href="' + url + '" ></a>';
    }
    popupHtml += '<div style="height: 20px;"></div>'; // see bottom of image for large one
    $('#screenshot_box').html(popupHtml);
    $('#screenshot_box').css({
        display: 'block',
        top: (document.documentElement.scrollTop + 100) + 'px'
    });
    $("#gray_out").fadeIn();
}

function submitPublish(id, type) {
    $("#PromptForm").submit();
}

function editTemplateElement(type, id) {
    simplePopup("/template_elements/edit/" + type + "/" + id);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,7 +97,9 @@
     if (!url.startsWith('data:image/')) {
         url = url.slice(0, -1);
     }
-    popupHtml = '<it class="fa fa-spin fa-spinner" style="font-size: xx-large; color: white; position: fixed; left: 50%; top: 50%;"></it>'
+    popupHtml = '<it class="fa fa-spin fa-spinner" style="font-size: xx-large; color: white; position: fixed; left: 50%; top: 50%;"></it>';
+    url = $('<div>').text(url).html();
+    title = $('<div>').text(title).html();
     popupHtml += '<img class="screenshot_box-content hidden" src="' + url + '" id="screenshot-image" title="' + title + '" alt="' + title + '" onload="$(this).show(); $(this).parent().find(\'.fa-spinner\').remove();"/>';
     popupHtml += '<div class="close-icon useCursorPointer" onClick="closeScreenshot();"></div>';
     if (!url.startsWith('data:image/')) {
```
