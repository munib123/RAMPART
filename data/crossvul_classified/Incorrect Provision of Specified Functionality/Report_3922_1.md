# CrossVul Fix Pair: Incorrect Provision of Specified Functionality in python
**Pair ID:** 3922_1
**Vulnerability Class:** Incorrect Provision of Specified Functionality
**CWE:** CWE-684
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3922_1`)

## Vulnerability Information & PoC

## Description
Incorrect Provision of Specified Functionality - When providing functionality to an external party, it is important that the product behaves in accordance with the details specified.

## Vulnerable Code
```python
Lines 1433-1473 of the vulnerable file.

        else:
            self._update_load_status(ok)

        if not ok:
            self.dump_async(functools.partial(
                self._error_page_workaround,
                self.settings.test_attribute('content.javascript.enabled')))

        if ok and self._reload_url is not None:
            # WORKAROUND for https://bugreports.qt.io/browse/QTBUG-66656
            log.config.debug(
                "Loading {} again because of config change".format(
                    self._reload_url.toDisplayString()))
            QTimer.singleShot(100, functools.partial(
                self.load_url, self._reload_url,
                emit_before_load_started=False))
            self._reload_url = None

    @pyqtSlot(certificateerror.CertificateErrorWrapper)
    def _on_ssl_errors(self, error):
        self._has_ssl_errors = True

        url = error.url()
        log.webview.debug("Certificate error: {}".format(error))

        if error.is_overridable():
            error.ignore = shared.ignore_certificate_errors(
                url, [error], abort_on=[self.abort_questions])
        else:
            log.webview.error("Non-overridable certificate error: "
                              "{}".format(error))

        log.webview.debug("ignore {}, URL {}, requested {}".format(
            error.ignore, url, self.url(requested=True)))

        # WORKAROUND for https://bugreports.qt.io/browse/QTBUG-56207
        show_cert_error = (
            not qtutils.version_check('5.9') and
            not error.ignore
        )
        # WORKAROUND for https://codereview.qt-project.org/c/qt/qtwebengine/+/270556
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1450,9 +1450,9 @@
 
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
