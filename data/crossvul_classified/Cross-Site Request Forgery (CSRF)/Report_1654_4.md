# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in python
**Pair ID:** 1654_4
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1654_4`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```python
Lines 687-727 of the vulnerable file.


        fields = dict(email="permless@django-cms.org", is_staff=True)

        if (User.USERNAME_FIELD != 'email'):
            fields[User.USERNAME_FIELD] = "permless"

        usr = User(**fields)
        usr.set_password(getattr(usr, User.USERNAME_FIELD))
        usr.save()
        return usr

    def get_page(self):
        return self.page

    def test_change_publish_unpublish(self):
        page = self.get_page()
        permless = self.get_permless()
        with self.login_user_context(permless):
            request = self.get_request()
            response = self.admin_class.publish_page(request, page.pk, "en")
            self.assertEqual(response.status_code, 403)
            page = self.reload(page)
            self.assertFalse(page.is_published('en'))

            request = self.get_request(post_data={'no': 'data'})
            response = self.admin_class.publish_page(request, page.pk, "en")
            # Forbidden
            self.assertEqual(response.status_code, 403)
            self.assertFalse(page.is_published('en'))

        admin_user = self.get_admin()
        with self.login_user_context(admin_user):
            request = self.get_request(post_data={'no': 'data'})
            response = self.admin_class.publish_page(request, page.pk, "en")
            self.assertEqual(response.status_code, 302)

            page = self.reload(page)
            self.assertTrue(page.is_published('en'))

            response = self.admin_class.unpublish(request, page.pk, "en")
            self.assertEqual(response.status_code, 302)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -704,14 +704,14 @@
         with self.login_user_context(permless):
             request = self.get_request()
             response = self.admin_class.publish_page(request, page.pk, "en")
+            self.assertEqual(response.status_code, 405)
+            page = self.reload(page)
+            self.assertFalse(page.is_published('en'))
+
+            request = self.get_request(post_data={'no': 'data'})
+            response = self.admin_class.publish_page(request, page.pk, "en")
             self.assertEqual(response.status_code, 403)
             page = self.reload(page)
-            self.assertFalse(page.is_published('en'))
-
-            request = self.get_request(post_data={'no': 'data'})
-            response = self.admin_class.publish_page(request, page.pk, "en")
-            # Forbidden
-            self.assertEqual(response.status_code, 403)
             self.assertFalse(page.is_published('en'))
 
         admin_user = self.get_admin()
@@ -746,6 +746,10 @@
         admin_user = self.get_admin()
         with self.login_user_context(permless):
             request = self.get_request()
+            response = self.admin_class.change_innavigation(request, page.pk)
+            self.assertEqual(response.status_code, 405)
+        with self.login_user_context(permless):
+            request = self.get_request(post_data={'no': 'data'})
             response = self.admin_class.change_innavigation(request, page.pk)
             self.assertEqual(response.status_code, 403)
         with self.login_user_context(permless):
@@ -806,7 +810,7 @@
         admin_user = self.get_admin()
         self.page.publish("en")  # Ensure public copy exists before reverting
         with self.login_user_context(admin_user):
-            response = self.client.get(admin_reverse('cms_page_revert_page', args=(self.page.pk, 'en')))
+            response = self.client.post(admin_reverse('cms_page_revert_page', args=(self.page.pk, 'en')))
             self.assertEqual(response.status_code, 302)
             url = response['Location']
             self.assertTrue(url.endswith('?%s' % get_cms_setting('CMS_TOOLBAR_URL__EDIT_OFF')))
```
