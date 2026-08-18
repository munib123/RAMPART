# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in coffeescript
**Pair ID:** 5742_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** coffeescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5742_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```coffeescript
Lines 94-134 of the vulnerable file.

      @addPromptLabel = @options.addPromptLabel
      @model.bind "change", @render, @
  
    template: jade["profiles_page/detail_page/list.jade"]
    template_data: -> 
        addPromptLabel: @addPromptLabel
    elements:
      "ul": "ul"
      "a#add": "add_button"
      "input#add": "add_input"
      "span#add": "add_label"

    on_render: ->
      collection = new FON.CollectionController
        el: @ul
        collection: @model
        child_control: (model) ->
          FON.model_backed_template
            model: model
            tagName: "li"
            template: _.template("""<a href="#" class="delete"><img src="img/x-16.png"></a><a href="#" class="view">{{id}}</a>""")
            elements:
              ".delete": "delete"
              ".view": "view"
            on_render: (controller) ->
              controller.delete.click (event) ->
                FON.confirm_delete(model.id, "item", -> model.destroy()).render()
                false
              controller.view.click (event) ->
                e = new EditConfigDialog
                  model: model
                e.render()
                false

      @add_button.click (event) =>
        if @add_input.val() != ""
          @do_add(@add_input.val())
      @add_input.keydown (event) =>
        if event.which == 13
          @do_add(@add_input.val())
        else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -111,7 +111,7 @@
           FON.model_backed_template
             model: model
             tagName: "li"
-            template: _.template("""<a href="#" class="delete"><img src="img/x-16.png"></a><a href="#" class="view">{{id}}</a>""")
+            template: _.template("""<a href="#" class="delete"><img src="img/x-16.png"></a><a href="#" class="view">{{FON.escapeHtml(id)}}</a>""")
             elements:
               ".delete": "delete"
               ".view": "view"
@@ -166,7 +166,7 @@
           FON.model_backed_template
             model: model
             tagName: "li"
-            template: _.template('<a href=#/containers/{{id}}>{{id}}</a>')
+            template: _.template('<a href=#/containers/{{id}}>{{FON.escapeHtml(id)}}</a>')
 
 
   class ValueListEntry extends FON.TemplateController
```
