# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3530_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3530_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 18-58 of the vulnerable file.

    this.width = width;
    this.height = height;
    this.hasDraft = false;
    this.comments = [];
    this.canDelete = false;
    this.draftComment = null;

    this.el = $('<div class="selection"/>').appendTo(container);
    this.tooltip = $.tooltip(this.el, {
        side: "lrbt"
    }).addClass("comments");
    this.flag = $('<div class="selection-flag"/>').appendTo(this.el);

    /*
     * Find out if there's any draft comments, and filter them out of the
     * stored list of comments.
     */
    if (comments && comments.length > 0) {
        for (var i in comments) {
            var comment = comments[i];

            if (comment.localdraft) {
                this._createDraftComment(comment.text);
            } else {
                this.comments.push(comment);
            }
        }
    } else {
        this._createDraftComment();
    }

    this.el
        .move(this.x, this.y, "absolute")
        .width(this.width)
        .height(this.height);

    this.updateCount();
    this.updateTooltip();

    return this;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,6 +35,9 @@
     if (comments && comments.length > 0) {
         for (var i in comments) {
             var comment = comments[i];
+
+            // We load in encoded text, so decode it.
+            comment.text = $("<div/>").html(comment.text).text();
 
             if (comment.localdraft) {
                 this._createDraftComment(comment.text);
```
