# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 4833_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4833_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 36-76 of the vulnerable file.



def apply_settings(settings, opts):
    settings.setFontSize(QWebSettings.DefaultFontSize, opts.default_font_size)
    settings.setFontSize(QWebSettings.DefaultFixedFontSize, opts.mono_font_size)
    settings.setFontSize(QWebSettings.MinimumLogicalFontSize, opts.minimum_font_size)
    settings.setFontSize(QWebSettings.MinimumFontSize, opts.minimum_font_size)
    settings.setFontFamily(QWebSettings.StandardFont, {'serif':opts.serif_family, 'sans':opts.sans_family, 'mono':opts.mono_family}[opts.standard_font])
    settings.setFontFamily(QWebSettings.SerifFont, opts.serif_family)
    settings.setFontFamily(QWebSettings.SansSerifFont, opts.sans_family)
    settings.setFontFamily(QWebSettings.FixedFont, opts.mono_family)
    settings.setAttribute(QWebSettings.ZoomTextOnly, True)


def apply_basic_settings(settings):
    # Security
    settings.setAttribute(QWebSettings.JavaEnabled, False)
    settings.setAttribute(QWebSettings.PluginsEnabled, False)
    settings.setAttribute(QWebSettings.JavascriptCanOpenWindows, False)
    settings.setAttribute(QWebSettings.JavascriptCanAccessClipboard, False)
    # PrivateBrowsing disables console messages
    # settings.setAttribute(QWebSettings.PrivateBrowsingEnabled, True)
    settings.setAttribute(QWebSettings.NotificationsEnabled, False)
    settings.setThirdPartyCookiePolicy(QWebSettings.AlwaysBlockThirdPartyCookies)

    # Miscellaneous
    settings.setAttribute(QWebSettings.LinksIncludedInFocusChain, True)
    settings.setAttribute(QWebSettings.DeveloperExtrasEnabled, True)


class Document(QWebPage):  # {{{

    page_turn = pyqtSignal(object)
    mark_element = pyqtSignal(QWebElement)
    settings_changed = pyqtSignal()
    animated_scroll_done_signal = pyqtSignal()

    def set_font_settings(self, opts):
        settings = self.settings()
        apply_settings(settings, opts)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,6 +53,7 @@
     settings.setAttribute(QWebSettings.PluginsEnabled, False)
     settings.setAttribute(QWebSettings.JavascriptCanOpenWindows, False)
     settings.setAttribute(QWebSettings.JavascriptCanAccessClipboard, False)
+    settings.setAttribute(QWebSettings.LocalContentCanAccessFileUrls, False)  # ensure javascript cannot read from local files
     # PrivateBrowsing disables console messages
     # settings.setAttribute(QWebSettings.PrivateBrowsingEnabled, True)
     settings.setAttribute(QWebSettings.NotificationsEnabled, False)
@@ -1435,5 +1436,3 @@
             self.link_clicked(qurl)
 
 # }}}
-
-
```
