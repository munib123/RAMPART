# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2445_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2445_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 39-79 of the vulnerable file.

    url = "/sightings/quickDelete/" + id + "/" + rawId + "/" + context;
    $.get(url, function(data) {
        $("#confirmation_box").html(data);
        openPopup("#confirmation_box");
    });
}

function fetchAddSightingForm(type, attribute_id, page, onvalue) {
    var url = "/sightings/quickAdd/" + attribute_id + "/" + type;
    if (onvalue) {
        url = url + "/1";
    } else {
        url = url + "/0";
    }
    $.get(url, function(data) {
        $("#confirmation_box").html(data);
        openPopup("#confirmation_box");
    });
}

function flexibleAddSighting(clicked, type, attribute_id, event_id, value, page, placement) {
    var $clicked = $(clicked);
    var hoverbroken = false;
    $clicked.off('mouseleave.temp').on('mouseleave.temp', function() {
        hoverbroken = true;
    });
    setTimeout(function() {
        $clicked.off('mouseleave.temp');
        if ($clicked.is(":hover") && !hoverbroken) {
            var html = '<div>'
                + '<button class="btn btn-primary" onclick="addSighting(\'' + type + '\', \'' + attribute_id + '\', \'' + event_id + '\', \'' + page + '\')">This attribute</button>'
                + '<button class="btn btn-primary" style="margin-left:5px;" onclick="fetchAddSightingForm(\'' + type + '\', \'' + attribute_id + '\', \'' + page + '\', true)">Global value</button>'
                + '</div>';
            openPopover(clicked, html, true, placement);
        }
    }, 1000);
}

function publishPopup(id, type) {
    var action = "alert";
    if (type == "publish") action = "publish";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,7 +56,7 @@
     });
 }
 
-function flexibleAddSighting(clicked, type, attribute_id, event_id, value, page, placement) {
+function flexibleAddSighting(clicked, type, attribute_id, event_id, page, placement) {
     var $clicked = $(clicked);
     var hoverbroken = false;
     $clicked.off('mouseleave.temp').on('mouseleave.temp', function() {
```
