# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in python
**Pair ID:** 1654_5
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1654_5`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```python
Lines 325-365 of the vulnerable file.

        self.assertEqual(pages_from_output, 1)
        self.assertEqual(published_from_output, 1)

    def tearDown(self):
        plugin_pool.patched = False
        plugin_pool.set_plugin_meta()


class PublishingTests(TestCase):
    def create_page(self, title=None, **kwargs):
        return create_page(title or self._testMethodName,
                           "nav_playground.html", "en", **kwargs)

    def test_publish_home(self):
        name = self._testMethodName
        page = self.create_page(name, published=False)
        self.assertFalse(page.publisher_public_id)
        self.assertEqual(Page.objects.all().count(), 1)
        superuser = self.get_superuser()
        with self.login_user_context(superuser):
            response = self.client.get(admin_reverse("cms_page_publish_page", args=[page.pk, 'en']))
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response['Location'], "http://testserver/en/?%s" % get_cms_setting('CMS_TOOLBAR_URL__EDIT_OFF'))

    def test_publish_single(self):
        name = self._testMethodName
        page = self.create_page(name, published=False)
        self.assertFalse(page.is_published('en'))

        drafts = Page.objects.drafts()
        public = Page.objects.public()
        published = Page.objects.public().published("en")
        self.assertObjectExist(drafts, title_set__title=name)
        self.assertObjectDoesNotExist(public, title_set__title=name)
        self.assertObjectDoesNotExist(published, title_set__title=name)

        page.publish("en")

        drafts = Page.objects.drafts()
        public = Page.objects.public()
        published = Page.objects.public().published("en")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -342,7 +342,7 @@
         self.assertEqual(Page.objects.all().count(), 1)
         superuser = self.get_superuser()
         with self.login_user_context(superuser):
-            response = self.client.get(admin_reverse("cms_page_publish_page", args=[page.pk, 'en']))
+            response = self.client.post(admin_reverse("cms_page_publish_page", args=[page.pk, 'en']))
             self.assertEqual(response.status_code, 302)
             self.assertEqual(response['Location'], "http://testserver/en/?%s" % get_cms_setting('CMS_TOOLBAR_URL__EDIT_OFF'))
 
@@ -381,7 +381,7 @@
         page = self.create_page("test_admin", published=False)
         superuser = self.get_superuser()
         with self.login_user_context(superuser):
-            response = self.client.get(admin_reverse("cms_page_publish_page", args=[page.pk, 'en']))
+            response = self.client.post(admin_reverse("cms_page_publish_page", args=[page.pk, 'en']))
             self.assertEqual(response.status_code, 302)
         page = Page.objects.get(pk=page.pk)
 
@@ -396,7 +396,7 @@
             ):
             with self.login_user_context(superuser):
                 with force_language('de'):
-                    response = self.client.get(admin_reverse("cms_page_publish_page", args=[page.pk, 'en']))
+                    response = self.client.post(admin_reverse("cms_page_publish_page", args=[page.pk, 'en']))
         self.assertEqual(response.status_code, 302)
         page = Page.objects.get(pk=page.pk)
 
```
