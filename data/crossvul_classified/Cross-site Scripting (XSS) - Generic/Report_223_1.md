# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 223_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `223_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 85-125 of the vulnerable file.

                    form.slideDown(1000, function () {
                        // Explicit show() call fixes IE7
                        $(this).show();
                    });
                }
            });
        });
    };

    /**
     * Add remove/undo buttons for removing a tag.
     *
     * @param {string} tag Tag to add buttons for.
     */
    Omeka.Items.addTagElement = function (tag) {
        var tagLi = $('<li/>');
        tagLi.after(" ");

        var undoButton = $('<span class="undo-remove-tag"><a href="#">Undo</a></span>').appendTo(tagLi);
        var deleteButton = $('<span class="remove-tag"><a href="#">Remove</a></span>').appendTo(tagLi);
        tagLi.prepend('<span class="tag">' + tag + '</span>');

        if($('#all-tags-list').length != 0) {
            $('#all-tags-list').append(tagLi);
        } else {
            $('#all-tags').append($('<h3>All Tags</h3><div class="tag-list"><ul id="all-tags-list"></ul></div>'));
            $('#all-tags-list').append(tagLi);
        }

        Omeka.Items.updateTagsField();
        return false;
    };


    /**
     * Add tag elements for new tags from the input box.
     *
     * @param {string} tags Comma-separated tags to be added.
     */
    Omeka.Items.addTags = function (tags) {
        var newTags = tags.split(Omeka.Items.tagDelimiter);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -102,7 +102,7 @@
 
         var undoButton = $('<span class="undo-remove-tag"><a href="#">Undo</a></span>').appendTo(tagLi);
         var deleteButton = $('<span class="remove-tag"><a href="#">Remove</a></span>').appendTo(tagLi);
-        tagLi.prepend('<span class="tag">' + tag + '</span>');
+        $('<span></span>', {'class': 'tag', 'text': tag}).appendTo(tagLi);
 
         if($('#all-tags-list').length != 0) {
             $('#all-tags-list').append(tagLi);
```
