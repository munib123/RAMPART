# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 1532_5
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1532_5`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 1-21 of the vulnerable file.

// Return the ElementType element type of the given element.
function typeForElement(el) {
  // TODO: handle background images that aren't just the BODY.
  switch (el.nodeName.toUpperCase()) {
    case 'INPUT':
    case 'IMG': return ElementTypes.image;
    case 'SCRIPT': return ElementTypes.script;
    case 'OBJECT':
    case 'EMBED': return ElementTypes.object;
    case 'VIDEO':
    case 'AUDIO':
    case 'SOURCE': return ElementTypes.media;
    case 'FRAME':
    case 'IFRAME': return ElementTypes.subdocument;
    case 'LINK':
      // favicons are reported as 'other' by onBeforeRequest.
      // if this is changed, we should update this too.
      if (/(^|\s)icon($|\s)/i.test(el.rel))
        return ElementTypes.other;
      return ElementTypes.stylesheet;
    case 'BODY': return ElementTypes.background;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,6 @@
+//cache a reference to window.confirm
+//so that web sites can not clobber the default implementation
+var abConfirm = window.confirm;
 // Return the ElementType element type of the given element.
 function typeForElement(el) {
   // TODO: handle background images that aren't just the BODY.
@@ -142,16 +145,18 @@
       var reqLoc = queryparts.requiresLocation;
       var reqList = (reqLoc ? "url:" + reqLoc : undefined);
       var title = queryparts.title;
-      BGcall("subscribe", {id: "url:" + loc, requires: reqList, title: title});
-      // Open subscribe popup
-      if (SAFARI) {
+      if (abConfirm(translate("subscribeconfirm", (title || loc)))) {
+        BGcall("subscribe", {id: "url:" + loc, requires: reqList, title: title});
+        // Open subscribe popup
+        if (SAFARI) {
           // In Safari, window.open() cannot be used
           // to open a new window from our global HTML file
           window.open(chrome.extension.getURL('pages/subscribe.html?' + loc),
                       "_blank",
                       'scrollbars=0,location=0,resizable=0,width=450,height=150');
-      } else {
+        } else {
           BGcall("launch_subscribe_popup", loc);
+        }
       }
     }
   };
```
