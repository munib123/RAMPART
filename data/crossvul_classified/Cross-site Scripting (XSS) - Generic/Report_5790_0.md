# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 5790_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5790_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 292-332 of the vulnerable file.


    def test_current_site_in_context_after_login(self):
        response = self.client.get(reverse('django.contrib.auth.views.login'))
        self.assertEqual(response.status_code, 200)
        if Site._meta.installed:
            site = Site.objects.get_current()
            self.assertEqual(response.context['site'], site)
            self.assertEqual(response.context['site_name'], site.name)
        else:
            self.assertIsInstance(response.context['site'], RequestSite)
        self.assertTrue(isinstance(response.context['form'], AuthenticationForm),
                     'Login form is not an AuthenticationForm')

    def test_security_check(self, password='password'):
        login_url = reverse('django.contrib.auth.views.login')

        # Those URLs should not pass the security check
        for bad_url in ('http://example.com',
                        'https://example.com',
                        'ftp://exampel.com',
                        '//example.com'):

            nasty_url = '%(url)s?%(next)s=%(bad_url)s' % {
                'url': login_url,
                'next': REDIRECT_FIELD_NAME,
                'bad_url': urllib.quote(bad_url),
            }
            response = self.client.post(nasty_url, {
                'username': 'testclient',
                'password': password,
            })
            self.assertEqual(response.status_code, 302)
            self.assertFalse(bad_url in response['Location'],
                             "%s should be blocked" % bad_url)

        # These URLs *should* still pass the security check
        for good_url in ('/view/?param=http://example.com',
                         '/view/?param=https://example.com',
                         '/view?param=ftp://exampel.com',
                         'view/?param=//example.com',
                         'https:///',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -309,7 +309,8 @@
         for bad_url in ('http://example.com',
                         'https://example.com',
                         'ftp://exampel.com',
-                        '//example.com'):
+                        '//example.com',
+                        'javascript:alert("XSS")'):
 
             nasty_url = '%(url)s?%(next)s=%(bad_url)s' % {
                 'url': login_url,
@@ -330,6 +331,7 @@
                          '/view?param=ftp://exampel.com',
                          'view/?param=//example.com',
                          'https:///',
+                         'HTTPS:///',
                          '//testserver/',
                          '/url%20with%20spaces/'):  # see ticket #12534
             safe_url = '%(url)s?%(next)s=%(good_url)s' % {
@@ -467,7 +469,8 @@
         for bad_url in ('http://example.com',
                         'https://example.com',
                         'ftp://exampel.com',
-                        '//example.com'):
+                        '//example.com',
+                        'javascript:alert("XSS")'):
             nasty_url = '%(url)s?%(next)s=%(bad_url)s' % {
                 'url': logout_url,
                 'next': REDIRECT_FIELD_NAME,
@@ -486,6 +489,7 @@
                          '/view?param=ftp://exampel.com',
                          'view/?param=//example.com',
                          'https:///',
+                         'HTTPS:///',
                          '//testserver/',
                          '/url%20with%20spaces/'):  # see ticket #12534
             safe_url = '%(url)s?%(next)s=%(good_url)s' % {
```
