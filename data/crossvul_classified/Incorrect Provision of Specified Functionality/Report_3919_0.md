# CrossVul Fix Pair: Incorrect Provision of Specified Functionality in python
**Pair ID:** 3919_0
**Vulnerability Class:** Incorrect Provision of Specified Functionality
**CWE:** CWE-684
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3919_0`)

## Vulnerability Information & PoC

## Description
Incorrect Provision of Specified Functionality - When providing functionality to an external party, it is important that the product behaves in accordance with the details specified.

## Vulnerable Code
```python
Lines 852-892 of the vulnerable file.

    #: Signal emitted when a tab's content size changed
    #: (new size as QSizeF)
    contents_size_changed = pyqtSignal(QSizeF)
    #: Signal emitted when a page requested full-screen (bool)
    fullscreen_requested = pyqtSignal(bool)
    #: Signal emitted before load starts (URL as QUrl)
    before_load_started = pyqtSignal(QUrl)

    # Signal emitted when a page's load status changed
    # (argument: usertypes.LoadStatus)
    load_status_changed = pyqtSignal(usertypes.LoadStatus)
    # Signal emitted before shutting down
    shutting_down = pyqtSignal()
    # Signal emitted when a history item should be added
    history_item_triggered = pyqtSignal(QUrl, QUrl, str)
    # Signal emitted when the underlying renderer process terminated.
    # arg 0: A TerminationStatus member.
    # arg 1: The exit code.
    renderer_process_terminated = pyqtSignal(TerminationStatus, int)

    def __init__(self, *, win_id: int, private: bool,
                 parent: QWidget = None) -> None:
        self.is_private = private
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
        self._widget = typing.cast(QWidget, None)
        self._progress = 0
        self._has_ssl_errors = False
        self._load_status = usertypes.LoadStatus.none
        self._tab_event_filter = eventfilter.TabEventFilter(
            self, parent=self)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -869,6 +869,13 @@
     # arg 1: The exit code.
     renderer_process_terminated = pyqtSignal(TerminationStatus, int)
 
+    # Hosts for which a certificate error happened. Shared between all tabs.
+    #
+    # Note that we remember hosts here, without scheme/port:
+    # QtWebEngine/Chromium also only remembers hostnames, and certificates are
+    # for a given hostname anyways.
+    _insecure_hosts = set()  # type: typing.Set[str]
+
     def __init__(self, *, win_id: int, private: bool,
                  parent: QWidget = None) -> None:
         self.is_private = private
@@ -886,7 +893,6 @@
         self._layout = miscwidgets.WrapperLayout(self)
         self._widget = typing.cast(QWidget, None)
         self._progress = 0
-        self._has_ssl_errors = False
         self._load_status = usertypes.LoadStatus.none
         self._tab_event_filter = eventfilter.TabEventFilter(
             self, parent=self)
@@ -973,7 +979,6 @@
     @pyqtSlot()
     def _on_load_started(self) -> None:
         self._progress = 0
-        self._has_ssl_errors = False
         self.data.viewing_source = False
         self._set_load_status(usertypes.LoadStatus.loading)
         self.load_started.emit()
@@ -1032,9 +1037,12 @@
         Needs to be called by subclasses to trigger a load status update, e.g.
         as a response to a loadFinished signal.
         """
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
