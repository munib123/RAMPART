# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in coffeescript
**Pair ID:** 2106_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** coffeescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2106_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```coffeescript
Lines 305-346 of the vulnerable file.

            @html = ''
            return
        @html = @html.trim()

        if not @noUID
            @html = @html.insert(@html.indexOf('>'), " id=\"uid-#{@uid}\"")

        profiler.stop()

        children_html = ''
        if children
            for child in children
                @children.push child
                if not child.dom
                    children_html += @wrapChild(child)
        
        @html = @html.replace('<children>', children_html)
        
        
    s: (value) ->
        # TODO SANITIZE!
        value

    createDom: () ->
        ""

    setupDom: (dom) ->
        if @dom
            return
        if not dom
            dom = $$(@html)
        @dom = dom
        if @properties.visible != true and @dom and @dom.style
            @dom.style.display = 'none'
        for child in @children
            if child.dom
                @append(child)
            else
                if Control.prototype.setupDom != child.constructor.prototype.setupDom
                    key = child.constructor.name
                    profiler.setupDomStats[key] ?= 0
                    profiler.setupDomStats[key] += 1
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -322,8 +322,12 @@
         
         
     s: (value) ->
-        # TODO SANITIZE!
-        value
+        ('' + value) /* Forces the conversion to string. */
+        .replace(/&/g, '&amp;') /* This MUST be the 1st replacement. */
+            .replace(/'/g, '&apos;') /* The 4 other predefined entities, required. */
+            .replace(/"/g, '&quot;')
+            .replace(/</g, '&lt;')
+            .replace(/>/g, '&gt;')
 
     createDom: () ->
         ""
```
