# CrossVul Fix Pair: Incorrect Provision of Specified Functionality in python
**Pair ID:** 3923_2
**Vulnerability Class:** Incorrect Provision of Specified Functionality
**CWE:** CWE-684
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3923_2`)

## Vulnerability Information & PoC

## Description
Incorrect Provision of Specified Functionality - When providing functionality to an external party, it is important that the product behaves in accordance with the details specified.

## Vulnerable Code
```python
Lines 820-862 of the vulnerable file.


        log.webview.debug("target {} override {}".format(
            self.data.open_target, self.data.override_target))

        if self.data.override_target is not None:
            target = self.data.override_target
            self.data.override_target = None
        else:
            target = self.data.open_target

        if (navigation.navigation_type == navigation.Type.link_clicked and
                target != usertypes.ClickTarget.normal):
            tab = shared.get_tab(self.win_id, target)
            tab.load_url(navigation.url)
            self.data.open_target = usertypes.ClickTarget.normal
            navigation.accepted = False

        if navigation.is_main_frame:
            self.settings.update_for_url(navigation.url)

    @pyqtSlot()
    def _on_ssl_errors(self):
        self._has_ssl_errors = True

    def _connect_signals(self):
        view = self._widget
        page = view.page()
        frame = page.mainFrame()
        page.windowCloseRequested.connect(self.window_close_requested)
        page.linkHovered.connect(self.link_hovered)
        page.loadProgress.connect(self._on_load_progress)
        frame.loadStarted.connect(self._on_load_started)
        view.scroll_pos_changed.connect(self.scroller.perc_changed)
        view.titleChanged.connect(self.title_changed)
        view.urlChanged.connect(self._on_url_changed)
        view.shutting_down.connect(self.shutting_down)
        page.networkAccessManager().sslErrors.connect(self._on_ssl_errors)
        frame.loadFinished.connect(self._on_frame_load_finished)
        view.iconChanged.connect(self._on_webkit_icon_changed)
        page.frameCreated.connect(self._on_frame_created)
        frame.contentsSizeChanged.connect(self._on_contents_size_changed)
        frame.initialLayoutCompleted.connect(self._on_history_trigger)
        page.navigation_request.connect(self._on_navigation_request)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -837,9 +837,9 @@
         if navigation.is_main_frame:
             self.settings.update_for_url(navigation.url)
 
-    @pyqtSlot()
-    def _on_ssl_errors(self):
-        self._has_ssl_errors = True
+    @pyqtSlot('QNetworkReply*')
+    def _on_ssl_errors(self, reply):
+        self._insecure_hosts.add(reply.url().host())
 
     def _connect_signals(self):
         view = self._widget
```
