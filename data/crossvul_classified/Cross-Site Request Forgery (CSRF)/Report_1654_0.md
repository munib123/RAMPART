# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in python
**Pair ID:** 1654_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1654_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```python
Lines 911-951 of the vulnerable file.


    @require_POST
    @create_revision()
    def change_template(self, request, object_id):
        page = get_object_or_404(Page, pk=object_id)
        if not page.has_change_permission(request):
            return HttpResponseForbidden(force_unicode(_("You do not have permission to change the template")))

        to_template = request.POST.get("template", None)
        if to_template not in dict(get_cms_setting('TEMPLATES')):
            return HttpResponseBadRequest(force_unicode(_("Template not valid")))

        page.template = to_template
        page.save()
        if is_installed('reversion'):
            message = _("Template changed to %s") % dict(get_cms_setting('TEMPLATES'))[to_template]
            self.cleanup_history(page)
            helpers.make_revision_with_plugins(page, request.user, message)
        return HttpResponse(force_unicode(_("The template was successfully changed")))

    @wrap_transaction
    def move_page(self, request, page_id, extra_context=None):
        """
        Move the page to the requested target, at the given position
        """
        target = request.POST.get('target', None)
        position = request.POST.get('position', None)
        if target is None or position is None:
            return HttpResponseRedirect('../../')

        try:
            page = self.model.objects.get(pk=page_id)
            target = self.model.objects.get(pk=target)
        except self.model.DoesNotExist:
            return jsonify_request(HttpResponseBadRequest("error"))

        # does he haves permissions to do this...?
        if not page.has_move_page_permission(request) or \
                not target.has_add_permission(request):
            return jsonify_request(
                HttpResponseForbidden(force_unicode(_("Error! You don't have permissions to move this page. Please reload the page"))))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -928,6 +928,7 @@
             helpers.make_revision_with_plugins(page, request.user, message)
         return HttpResponse(force_unicode(_("The template was successfully changed")))
 
+    @require_POST
     @wrap_transaction
     def move_page(self, request, page_id, extra_context=None):
         """
@@ -1013,6 +1014,7 @@
                 helpers.make_revision_with_plugins(page, request.user, message)
             return HttpResponse("ok")
 
+    @require_POST
     @wrap_transaction
     def copy_page(self, request, page_id, extra_context=None):
         """
@@ -1046,6 +1048,7 @@
         context.update(extra_context or {})
         return HttpResponseRedirect('../../')
 
+    @require_POST
     @wrap_transaction
     @create_revision()
     def publish_page(self, request, page_id, language):
@@ -1146,6 +1149,7 @@
                         revision.delete()
                         deleted.append(revision.pk)
 
+    @require_POST
     @wrap_transaction
     def unpublish(self, request, page_id, language):
         """
@@ -1181,6 +1185,7 @@
             path = "%s?language=%s&page_id=%s" % (path, request.GET.get('redirect_language'), request.GET.get('redirect_page_id'))
         return HttpResponseRedirect(path)
 
+    @require_POST
     @wrap_transaction
     def revert_page(self, request, page_id, language):
         page = get_object_or_404(Page, id=page_id)
@@ -1316,6 +1321,7 @@
             page.site.domain, url)
         return HttpResponseRedirect(url)
 
+    @require_POST
     def change_innavigation(self, request, page_id):
         """
         Switch the in_navigation of a page
```
