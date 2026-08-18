# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3790_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3790_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 783-823 of the vulnerable file.


        var cmp = $('composeMessageParent').getLayout(),
            mah = document.viewport.getHeight() - cmp.get('top') - cmp.get('margin-box-height') + cmp.get('height');

        if (this.rte_loaded) {
            this.rte.resize('99%', mah - 1, false);
        } else if (!ImpComposeBase.editor_on) {
            $('composeMessage').setStyle({ height: mah + 'px' });
        }

        if ($('rteloading') && $('rteloading').visible()) {
            this.RTELoading();
        }
    },

    uploadAttachment: function()
    {
        var u = $('upload');
        this.uniqueSubmit('addAttachment');
        u.up().hide();
        $('upload_wait').update(DimpCore.text.uploading + ' (' + $F(u) + ')').show();
    },

    toggleCC: function(type)
    {
        var t = $('toggle' + type),
            s = t.siblings().first();

        new TextareaResize(type);

        $('send' + type).show();
        if (s && s.visible()) {
            t.hide();
        } else {
            t.up('TR').hide();
        }

        this.resizeMsgArea();
    },

    /* Open the addressbook window. */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -800,7 +800,7 @@
         var u = $('upload');
         this.uniqueSubmit('addAttachment');
         u.up().hide();
-        $('upload_wait').update(DimpCore.text.uploading + ' (' + $F(u) + ')').show();
+        $('upload_wait').update(DimpCore.text.uploading + ' (' + $F(u).escapeHTML() + ')').show();
     },
 
     toggleCC: function(type)
```
