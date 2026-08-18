# CrossVul Fix Pair: Incorrect Provision of Specified Functionality in python
**Pair ID:** 3918_0
**Vulnerability Class:** Incorrect Provision of Specified Functionality
**CWE:** CWE-684
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3918_0`)

## Vulnerability Information & PoC

## Description
Incorrect Provision of Specified Functionality - When providing functionality to an external party, it is important that the product behaves in accordance with the details specified.

## Vulnerable Code
```python
Lines 720-760 of the vulnerable file.

        predicted_navigation: Emitted before we tell Qt to open a URL.
    """

    window_close_requested = pyqtSignal()
    link_hovered = pyqtSignal(str)
    load_started = pyqtSignal()
    load_progress = pyqtSignal(int)
    load_finished = pyqtSignal(bool)
    icon_changed = pyqtSignal(QIcon)
    title_changed = pyqtSignal(str)
    load_status_changed = pyqtSignal(str)
    new_tab_requested = pyqtSignal(QUrl)
    url_changed = pyqtSignal(QUrl)
    shutting_down = pyqtSignal()
    contents_size_changed = pyqtSignal(QSizeF)
    add_history_item = pyqtSignal(QUrl, QUrl, str)  # url, requested url, title
    fullscreen_requested = pyqtSignal(bool)
    renderer_process_terminated = pyqtSignal(TerminationStatus, int)
    predicted_navigation = pyqtSignal(QUrl)

    def __init__(self, *, win_id, mode_manager, private, parent=None):
        self.private = private
        self.win_id = win_id
        self.tab_id = next(tab_id_gen)
        super().__init__(parent)

        self.registry = objreg.ObjectRegistry()
        tab_registry = objreg.get('tab-registry', scope='window',
                                  window=win_id)
        tab_registry[self.tab_id] = self
        objreg.register('tab', self, registry=self.registry)

        self.data = TabData()
        self._layout = miscwidgets.WrapperLayout(self)
        self._widget = None
        self._progress = 0
        self._has_ssl_errors = False
        self._mode_manager = mode_manager
        self._load_status = usertypes.LoadStatus.none
        self._mouse_event_filter = mouse.MouseEventFilter(
            self, parent=self)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -737,6 +737,13 @@
     renderer_process_terminated = pyqtSignal(TerminationStatus, int)
     predicted_navigation = pyqtSignal(QUrl)
 
+    # Hosts for which a certificate error happened. Shared between all tabs.
+    #
+    # Note that we remember hosts here, without scheme/port:
+    # QtWebEngine/Chromium also only remembers hostnames, and certificates are
+    # for a given hostname anyways.
+    _insecure_hosts = set()  # type: typing.Set[str]
+
     def __init__(self, *, win_id, mode_manager, private, parent=None):
         self.private = private
         self.win_id = win_id
@@ -753,7 +760,6 @@
         self._layout = miscwidgets.WrapperLayout(self)
         self._widget = None
         self._progress = 0
-        self._has_ssl_errors = False
         self._mode_manager = mode_manager
         self._load_status = usertypes.LoadStatus.none
         self._mouse_event_filter = mouse.MouseEventFilter(
@@ -840,7 +846,6 @@
     @pyqtSlot()
     def _on_load_started(self):
         self._progress = 0
-        self._has_ssl_errors = False
         self.data.viewing_source = False
         self._set_load_status(usertypes.LoadStatus.loading)
         self.load_started.emit()
@@ -899,9 +904,12 @@
         sess_manager = objreg.get('session-manager')
         sess_manager.save_autosave()
 
-        if ok and not self._has_ssl_errors:
+        if ok:
             if self.url().scheme() == 'https':
-                self._set_load_status(usertypes.LoadStatus.success_https)
+                if self.url().host() in self._insecure_hosts:
+                    self._set_load_status(usertypes.LoadStatus.warn)
+                else:
+                    self._set_load_status(usertypes.LoadStatus.success_https)
             else:
                 self._set_load_status(usertypes.LoadStatus.success)
         elif ok:
```
