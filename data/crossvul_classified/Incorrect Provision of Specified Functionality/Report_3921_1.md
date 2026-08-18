# CrossVul Fix Pair: Incorrect Provision of Specified Functionality in python
**Pair ID:** 3921_1
**Vulnerability Class:** Incorrect Provision of Specified Functionality
**CWE:** CWE-684
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3921_1`)

## Vulnerability Information & PoC

## Description
Incorrect Provision of Specified Functionality - When providing functionality to an external party, it is important that the product behaves in accordance with the details specified.

## Vulnerable Code
```python
Lines 1319-1359 of the vulnerable file.


        if ok and self._reload_url is not None:
            # WORKAROUND for https://bugreports.qt.io/browse/QTBUG-66656
            log.config.debug(
                "Loading {} again because of config change".format(
                    self._reload_url.toDisplayString()))
            QTimer.singleShot(100, functools.partial(self.openurl,
                                                     self._reload_url,
                                                     predict=False))
            self._reload_url = None

        if not qtutils.version_check('5.10', compiled=False):
            # We can't do this when we have the loadFinished workaround as that
            # sometimes clears icons without loading a new page.
            # In general, this is handled by Qt, but when loading takes long,
            # the old icon is still displayed.
            self.icon_changed.emit(QIcon())

    @pyqtSlot(certificateerror.CertificateErrorWrapper)
    def _on_ssl_errors(self, error):
        self._has_ssl_errors = True

        url = error.url()
        log.webview.debug("Certificate error: {}".format(error))

        if error.is_overridable():
            error.ignore = shared.ignore_certificate_errors(
                url, [error], abort_on=[self.shutting_down, self.load_started])
        else:
            log.webview.error("Non-overridable certificate error: "
                              "{}".format(error))

        log.webview.debug("ignore {}, URL {}, requested {}".format(
            error.ignore, url, self.url(requested=True)))

        # WORKAROUND for https://bugreports.qt.io/browse/QTBUG-56207
        # We can't really know when to show an error page, as the error might
        # have happened when loading some resource.
        # However, self.url() is not available yet and the requested URL
        # might not match the URL we get from the error - so we just apply a
        # heuristic here.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1336,9 +1336,9 @@
 
     @pyqtSlot(certificateerror.CertificateErrorWrapper)
     def _on_ssl_errors(self, error):
-        self._has_ssl_errors = True
-
         url = error.url()
+        self._insecure_hosts.add(url.host())
+
         log.webview.debug("Certificate error: {}".format(error))
 
         if error.is_overridable():
```
