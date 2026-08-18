# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2428_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2428_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1766-1806 of the vulnerable file.

    var innerDiv = createElement("div");
    eventCell.appendChild(innerDiv);
    innerDiv.addClassName("eventInside");
    innerDiv.addClassName("calendarFolder" + event[1]);
    if (eventRep.userState >= 0 && userStates[eventRep.userState])
        innerDiv.addClassName(userStates[eventRep.userState]);

    var gradientDiv = createElement("div");
    innerDiv.appendChild(gradientDiv);
    gradientDiv.addClassName("gradient");

    var gradientImg = createElement("img");
    gradientDiv.appendChild(gradientImg);
    gradientImg.src = ResourcesURL + "/event-gradient.png";

    var textDiv = createElement("div");
    innerDiv.appendChild(textDiv);
    textDiv.addClassName("text");
    var iconSpan = createElement("span", null, "icons");
    textDiv.appendChild(iconSpan);
    textDiv.appendChild(document.createTextNode(eventText.replace(/(\\r)?\\n/g, "<BR/>")));

    // Add alarm and classification icons
    if (event[9] == 1)
        createElement("img", null, null, {src: ResourcesURL + "/private.png"}, null, iconSpan);
    else if (event[9] == 2)
        createElement("img", null, null, {src: ResourcesURL + "/confidential.png"}, null, iconSpan);
    if (event[15] > 0)
        createElement("img", null, null, {src: ResourcesURL + "/alarm.png"}, null, iconSpan);

    if (event[10] != null) {
        var categoryStyle = categoriesStyles.get(event[10]);
        if (!categoryStyle) {
            categoryStyle = 'category_' + categoriesStyles.keys().length;
            categoriesStyles.set([event[10]], categoryStyle);
        }
        innerDiv.addClassName(categoryStyle);
    }
    eventCell.observe("contextmenu", onMenuCurrentView);

    if (event[3] == null) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1783,7 +1783,7 @@
     textDiv.addClassName("text");
     var iconSpan = createElement("span", null, "icons");
     textDiv.appendChild(iconSpan);
-    textDiv.appendChild(document.createTextNode(eventText.replace(/(\\r)?\\n/g, "<BR/>")));
+    textDiv.update(eventText.replace(/(\\r)?\\n/g, "<BR/>"));
 
     // Add alarm and classification icons
     if (event[9] == 1)
```
