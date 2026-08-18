# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in coffeescript
**Pair ID:** 5742_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** coffeescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5742_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```coffeescript
Lines 120-160 of the vulnerable file.


    do_delete: ->
      FON.confirm_delete(@state.get("selected").get("id"), "user", => 
        @state.get("selected").destroy()
        @state.set
          selected: null
      ).render()
      false

    on_render: ->
      @model.trigger "reset", @model
      @table = new UsersTable
        el: @$("#users")
        parent: @
        collection: @model
      @table.render()

  class RoleEntry extends FON.ModelBackedTemplate
    tagName:"li"

    template: _.template("""<a href="#" class="delete-role" title="Delete role"><img src="img/x-16.png"></a>{{id}}""")
    elements:
      "a.delete-role": "delete"

    on_render: ->
      @delete.click (event) =>
        FON.confirm_delete(@model.id, "role", => @model.destroy()).render()
        false


  class UserOverviewController extends FON.TemplateController
    template: jade["users_page/user_overview.jade"]
    template_data: ->  @model.toJSON()
    elements:
      "ul.roles": "ul_roles"
    on_render: ->

      ul = new FON.CollectionController
        el: @ul_roles
        collection: @model.roles()
        child_control: (model) ->
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -137,7 +137,7 @@
   class RoleEntry extends FON.ModelBackedTemplate
     tagName:"li"
 
-    template: _.template("""<a href="#" class="delete-role" title="Delete role"><img src="img/x-16.png"></a>{{id}}""")
+    template: _.template("""<a href="#" class="delete-role" title="Delete role"><img src="img/x-16.png"></a>{{FON.escapeHtml(id)}}""")
     elements:
       "a.delete-role": "delete"
 
```
