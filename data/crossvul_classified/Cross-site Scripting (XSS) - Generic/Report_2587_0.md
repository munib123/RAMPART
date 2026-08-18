# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in coffeescript
**Pair ID:** 2587_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** coffeescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2587_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```coffeescript
Lines 1-6 of the vulnerable file.

angular.module('loomioApp').config (markedProvider, renderProvider) ->
  markedProvider.setOptions
    gfm: true
    sanitize: true
    breaks: true
  markedProvider.setRenderer(renderProvider.$get(0).createRenderer())
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,22 @@
-angular.module('loomioApp').config (markedProvider, renderProvider) ->
-  markedProvider.setOptions
-    gfm: true
-    sanitize: true
-    breaks: true
-  markedProvider.setRenderer(renderProvider.$get(0).createRenderer())
+angular.module('loomioApp').config (markedProvider) ->
+  customRenderer = (opts) ->
+    _super   = new marked.Renderer(opts)
+    renderer = _.clone(_super)
+    cook = (text) ->
+      text = emojione.shortnameToImage(text)
+      text = text.replace(/\[\[@([a-zA-Z0-9]+)\]\]/g, "<a class='lmo-user-mention' href='/u/$1'>@$1</a>")
+      text
+
+    renderer.paragraph = (text) -> _super.paragraph cook(text)
+    renderer.listitem  = (text) -> _super.listitem  cook(text)
+    renderer.tablecell = (text) -> _super.tablecell cook(text)
+
+    renderer.heading   = (text, level) ->
+      _super.heading(emojione.shortnameToImage(text), level, text)
+
+    renderer.link      = (href, title, text) ->
+      _super.link(href, title, text).replace('<a ', '<a rel="noopener noreferrer" target="_blank" ')
+
+    renderer
+
+  markedProvider.setRenderer customRenderer(gfm: true, sanitize: true, breaks: true)
```
