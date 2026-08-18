# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 1735_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1735_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 13-53 of the vulnerable file.


    meta_type = 'Plone URL Tool'
    security = ClassSecurityInfo()
    toolicon = 'skins/plone_images/link_icon.png'

    security.declarePublic('isURLInPortal')
    def isURLInPortal(self, url, context=None):
        """ Check if a given url is on the same host and contains the portal
            path.  Used to ensure that login forms can determine relevant
            referrers (i.e. in portal).  Also return true for some relative
            urls if context is passed in to allow for url parsing. When context
            is not provided, assume that relative urls are in the portal. It is
            assumed that http://portal is the same portal as https://portal.

            External sites listed in 'allow_external_login_sites' of
            site_properties are also considered within the portal to allow for
            single sign on.
        """
        # sanitize url
        url = re.sub('^[\x00-\x20]+', '', url).strip()

        p_url = self()

        _, u_host, u_path, _, _, _ = urlparse(url)
        if not u_host and not u_path.startswith('/'):
            if context is None:
                return True  # old behavior
            if not context.isPrincipiaFolderish:
                useurl = context.aq_parent.absolute_url()
            else:
                useurl = context.absolute_url()
        else:
            useurl = p_url  # when u_path.startswith('/')
        if not useurl.endswith('/'):
            useurl += '/'

        # urljoin to current url to get an absolute path
        _, u_host, u_path, _, _, _ = urlparse(urljoin(useurl, url))

        # normalise to end with a '/' so /foobar is not considered within /foo
        if not u_path:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,9 @@
         """
         # sanitize url
         url = re.sub('^[\x00-\x20]+', '', url).strip()
+        if ('<script' in url or '%3Cscript' in url or 'javascript:' in url or
+                'javascript%3A' in url):
+            return False
 
         p_url = self()
 
```
