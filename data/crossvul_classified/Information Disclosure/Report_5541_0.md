# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 5541_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5541_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 92-132 of the vulnerable file.

        """
        Parse URLs. This method fixes an issue where credentials specified
        in the URL are interpreted differently in Python 2.6.1+ than prior
        versions of Python. It also deals with the peculiarity that new-style
        Swift URIs have where a username can contain a ':', like so:

            swift://account:user:pass@authurl.com/container/obj
        """
        # Make sure that URIs that contain multiple schemes, such as:
        # swift://user:pass@http://authurl.com/v1/container/obj
        # are immediately rejected.
        if uri.count('://') != 1:
            reason = _(
                    "URI cannot contain more than one occurrence of a scheme."
                    "If you have specified a URI like "
                    "swift://user:pass@http://authurl.com/v1/container/obj"
                    ", you need to change it to use the swift+http:// scheme, "
                    "like so: "
                    "swift+http://user:pass@authurl.com/v1/container/obj"
                    )
            logger.error(_("Invalid store uri %(uri)s: %(reason)s") % locals())
            raise exception.BadStoreUri()

        pieces = urlparse.urlparse(uri)
        assert pieces.scheme in ('swift', 'swift+http', 'swift+https')
        self.scheme = pieces.scheme
        netloc = pieces.netloc
        path = pieces.path.lstrip('/')
        if netloc != '':
            # > Python 2.6.1
            if '@' in netloc:
                creds, netloc = netloc.split('@')
            else:
                creds = None
        else:
            # Python 2.6.1 compat
            # see lp659445 and Python issue7904
            if '@' in path:
                creds, path = path.split('@')
            else:
                creds = None
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -109,7 +109,7 @@
                     "like so: "
                     "swift+http://user:pass@authurl.com/v1/container/obj"
                     )
-            logger.error(_("Invalid store uri %(uri)s: %(reason)s") % locals())
+            logger.error(_("Invalid store URI: %(reason)s") % locals())
             raise exception.BadStoreUri()
 
         pieces = urlparse.urlparse(uri)
@@ -139,8 +139,7 @@
             # the account and user. Combine them into a single username of
             # account:user
             if len(cred_parts) == 1:
-                reason = (_("Badly formed credentials '%(creds)s' in Swift "
-                            "URI") % locals())
+                reason = (_("Badly formed credentials in Swift URI."))
                 logger.error(reason)
                 raise exception.BadStoreUri()
             elif len(cred_parts) == 3:
@@ -161,7 +160,7 @@
                 path_parts.insert(0, netloc)
                 self.authurl = '/'.join(path_parts)
         except IndexError:
-            reason = _("Badly formed Swift URI: %s") % uri
+            reason = _("Badly formed Swift URI.")
             logger.error(reason)
             raise exception.BadStoreUri()
 
@@ -265,8 +264,8 @@
         except swift_client.ClientException, e:
             if e.http_status == httplib.NOT_FOUND:
                 uri = location.get_store_uri()
-                raise exception.NotFound(_("Swift could not find image at "
-                                         "uri %(uri)s") % locals())
+                msg = _("Swift could not find image at URI.")
+                raise exception.NotFound(msg)
             else:
                 raise
 
@@ -464,7 +463,7 @@
         except swift_client.ClientException, e:
             if e.http_status == httplib.CONFLICT:
                 raise exception.Duplicate(_("Swift already has an image at "
-                                          "location %s") % location.get_uri())
+                                          "this location."))
             msg = (_("Failed to add object to Swift.\n"
                    "Got error from Swift: %(e)s") % locals())
             logger.error(msg)
@@ -513,8 +512,8 @@
         except swift_client.ClientException, e:
             if e.http_status == httplib.NOT_FOUND:
                 uri = location.get_store_uri()
-                raise exception.NotFound(_("Swift could not find image at "
-                                         "uri %(uri)s") % locals())
+                msg = _("Swift could not find image at URI.")
+                raise exception.NotFound(msg)
             else:
                 raise
 
```
