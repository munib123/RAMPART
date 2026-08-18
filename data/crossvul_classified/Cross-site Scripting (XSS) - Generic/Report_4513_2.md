# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4513_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4513_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 192-232 of the vulnerable file.

        froalaOptions.placeholderText = placeholder ? placeholder : ''

        froalaOptions.height = this.$el.hasClass('stretch')
            ? Infinity
            : $('.height-indicator', this.$el).height()

        if (!this.options.useMediaManager) {
            delete $.FroalaEditor.PLUGINS.mediaManager
        }

        $.FroalaEditor.ICON_TEMPLATES = {
            font_awesome: '<i class="icon-[NAME]"></i>',
            text: '<span style="text-align: center;">[NAME]</span>',
            image: '<img src=[SRC] alt=[ALT] />'
        }

        this.$textarea.on('froalaEditor.initialized', this.proxy(this.build))
        this.$textarea.on('froalaEditor.contentChanged', this.proxy(this.onChange))
        this.$textarea.on('froalaEditor.html.get', this.proxy(this.onSyncContent))
        this.$textarea.on('froalaEditor.html.set', this.proxy(this.onSetContent))
        this.$form.on('oc.beforeRequest', this.proxy(this.onFormBeforeRequest))

        this.$textarea.froalaEditor(froalaOptions)

        this.editor = this.$textarea.data('froala.editor')

        if (this.options.readOnly) {
            this.editor.edit.off()
        }

        this.$el.on('keydown', '.fr-view figure', this.proxy(this.onFigureKeydown))
    }

    RichEditor.prototype.dispose = function() {
        this.unregisterHandlers()

        this.$textarea.froalaEditor('destroy')

        this.$el.removeData('oc.richEditor')

        this.options = null
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -209,6 +209,7 @@
         this.$textarea.on('froalaEditor.contentChanged', this.proxy(this.onChange))
         this.$textarea.on('froalaEditor.html.get', this.proxy(this.onSyncContent))
         this.$textarea.on('froalaEditor.html.set', this.proxy(this.onSetContent))
+        this.$textarea.on('froalaEditor.paste.beforeCleanup', this.proxy(this.beforeCleanupPaste))
         this.$form.on('oc.beforeRequest', this.proxy(this.onFormBeforeRequest))
 
         this.$textarea.froalaEditor(froalaOptions)
@@ -245,6 +246,7 @@
         this.$textarea.off('froalaEditor.contentChanged', this.proxy(this.onChange))
         this.$textarea.off('froalaEditor.html.get', this.proxy(this.onSyncContent))
         this.$textarea.off('froalaEditor.html.set', this.proxy(this.onSetContent))
+        this.$textarea.off('froalaEditor.paste.beforeCleanup', this.proxy(this.beforeCleanupPaste))
         this.$form.off('oc.beforeRequest', this.proxy(this.onFormBeforeRequest))
 
         $(window).off('resize', this.proxy(this.updateLayout))
@@ -342,6 +344,10 @@
 
     RichEditor.prototype.onSetContent = function(ev, editor) {
         this.$textarea.trigger('setContent.oc.richeditor', [this])
+    }
+
+    RichEditor.prototype.beforeCleanupPaste = function (ev, editor, clipboard_html) {
+        return ocSanitize(clipboard_html)
     }
 
     RichEditor.prototype.onSyncContent = function(ev, editor, html) {
```
