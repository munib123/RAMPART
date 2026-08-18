# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 4833_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4833_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 128-168 of the vulnerable file.

            if pi.parsing_done and pi.length == ldata and pi.fingerprint == hdata:
                return
            pi.parsed_data = None
            pi.parsing_done = False
        pi.length, pi.fingerprint = ldata, hdata
        self.requests.put((self.request_count, pi, data))
        self.request_count += 1

    def shutdown(self):
        self.requests.put(shutdown)

    def get_data(self, name):
        return getattr(self.parse_items.get(name, None), 'parsed_data', None)

    def clear(self):
        self.parse_items.clear()

    def is_alive(self):
        return Thread.is_alive(self) or (hasattr(self, 'worker') and self.worker.is_alive())

parse_worker = ParseWorker()
# }}}

# Override network access to load data "live" from the editors {{{


class NetworkReply(QNetworkReply):

    def __init__(self, parent, request, mime_type, name):
        QNetworkReply.__init__(self, parent)
        self.setOpenMode(QNetworkReply.ReadOnly | QNetworkReply.Unbuffered)
        self.setRequest(request)
        self.setUrl(request.url())
        self._aborted = False
        if mime_type in OEB_DOCS:
            self.resource_name = name
            QTimer.singleShot(0, self.check_for_parse)
        else:
            data = get_data(name)
            if isinstance(data, type('')):
                data = data.encode('utf-8')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -145,6 +145,7 @@
     def is_alive(self):
         return Thread.is_alive(self) or (hasattr(self, 'worker') and self.worker.is_alive())
 
+
 parse_worker = ParseWorker()
 # }}}
 
@@ -280,6 +281,7 @@
         settings.setAttribute(settings.PrivateBrowsingEnabled, True)
         settings.setAttribute(settings.JavascriptCanOpenWindows, False)
         settings.setAttribute(settings.JavascriptCanAccessClipboard, False)
+        settings.setAttribute(settings.LocalContentCanAccessFileUrls, False)  # ensure javascript cannot read from local files
         settings.setAttribute(settings.LinksIncludedInFocusChain, False)
         settings.setAttribute(settings.DeveloperExtrasEnabled, True)
         settings.setDefaultTextEncoding('utf-8')
```
