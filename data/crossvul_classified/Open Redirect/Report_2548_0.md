# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 2548_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2548_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 64-104 of the vulnerable file.

    :func:`tg.url` in the template).  In addition to the functionality that
    :func:`tg.url` provides, it adds a token to prevent :term:`CSRF` attacks.

    :arg tgpath:  a list or a string. If the path is absolute (starts
        with a "/"), the :attr:`server.webpath`, :envvar:`SCRIPT_NAME` and
        the approot of the application are prepended to the path. In order for
        the approot to be detected properly, the root object should extend
        :class:`turbogears.controllers.RootController`.
    :kwarg tgparams: See param: ``kwargs``
    :kwarg kwargs: Query parameters for the URL can be passed in as a
        dictionary in the second argument *or* as keyword parameters.
        Values which are a list or a tuple are used to create multiple
        key-value pairs.
    :returns: The changed path

    .. versionadded:: 0.3.10
       Modified from turbogears.controllers.url for :ref:`CSRF-Protection`
    '''
    if not isinstance(tgpath, six.string_types):
        tgpath = '/'.join(list(tgpath))
    if tgpath.startswith('/'):
        webpath = (config.get('server.webpath') or '').rstrip('/')
        if tg_util.request_available():
            check_app_root()
            tgpath = request.app_root + tgpath
            try:
                webpath += request.wsgi_environ['SCRIPT_NAME'].rstrip('/')
            except (AttributeError, KeyError):  # pylint: disable-msg=W0704
                # :W0704: Lack of wsgi environ is fine... we still have
                # server.webpath
                pass
        tgpath = webpath + tgpath
    if tgparams is None:
        tgparams = kwargs
    else:
        try:
            tgparams = tgparams.copy()
            tgparams.update(kwargs)
        except AttributeError:
            raise TypeError(
                'url() expects a dictionary for query parameters')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -81,6 +81,11 @@
     '''
     if not isinstance(tgpath, six.string_types):
         tgpath = '/'.join(list(tgpath))
+    if not tgpath.startswith('/'):
+        # Do not allow the url() function to be used for external urls.
+        # This function is primarily used in redirect() calls, so this prevents
+        # covert redirects and thus CSRF leaking.
+        tgpath = '/'
     if tgpath.startswith('/'):
         webpath = (config.get('server.webpath') or '').rstrip('/')
         if tg_util.request_available():
```
