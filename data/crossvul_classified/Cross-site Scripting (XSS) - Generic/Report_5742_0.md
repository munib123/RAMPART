# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in coffeescript
**Pair ID:** 5742_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** coffeescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5742_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```coffeescript
Lines 112-152 of the vulnerable file.


          error: (data, textStatus, errorThrown) =>
            @file_input.val ""
            @upload_button.addClass 'disabled'
            app.flash
              kind: "error"
              title: "Error uploading patch file: "
              message: data.responseText
        false


      version_control = new FON.CollectionController
        el: @version_select
        collection: @versions
        child_control: (model) ->
          FON.model_backed_template
            model: model
            tagName: "option"
            attr:
              "value": model.id
            template: _.template("#{model.id}")
        on_render: =>
          super
          if @versions.get(@version.id)
            @version_select.val(@version.id)
          else
            @version = @versions.default_version()
            @version_select.val(@versions.default_version().id)

      version_control.render()

      @version_select.change =>
        @version = @versions.get(@version_select.val())

      file_listing = new FON.CollectionController
        el: @patch_list
        collection: @patch_files
        child_control: (model) ->
          FON.model_backed_template
            model: model
            tagName: "li"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -129,7 +129,7 @@
             tagName: "option"
             attr:
               "value": model.id
-            template: _.template("#{model.id}")
+            template: _.template("#{FON.escapeHtml(model.id)}")
         on_render: =>
           super
           if @versions.get(@version.id)
@@ -150,7 +150,7 @@
           FON.model_backed_template
             model: model
             tagName: "li"
-            template: _.template("""<a href="#" class="delete"><img src="img/x-16.png"></a>#{model.id}""")
+            template: _.template("""<a href="#" class="delete"><img src="img/x-16.png"></a>#{FON.escapeHtml(model.id)}""")
             elements:
               ".delete": "delete"
             on_render: (controller) ->
```
