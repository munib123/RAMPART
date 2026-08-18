# CrossVul Fix Pair: Improper Authentication in html
**Pair ID:** 2505_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2505_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```html
Lines 1-17 of the vulnerable file.

{% extends "zerver/portico.html" %}

{% block portico_content %}

<div class="pitch">
    <hr/>
    <p class="lead">Whoops. The confirmation link has expired.</p>

    <p>
        If you're not sure how to generate a new one, shoot us a line at
        <a href="mailto:{{ support_email }}">{{ support_email }}</a>
        and we'll get this resolved shortly.
    </p>

</div>

{% endblock %}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,12 +4,10 @@
 
 <div class="pitch">
     <hr/>
-    <p class="lead">Whoops. The confirmation link has expired.</p>
+    <p class="lead">Whoops. The confirmation link has expired or been deactivated.</p>
 
     <p>
-        If you're not sure how to generate a new one, shoot us a line at
-        <a href="mailto:{{ support_email }}">{{ support_email }}</a>
-        and we'll get this resolved shortly.
+        Please contact your organization administrator for a new one.
     </p>
 
 </div>
```
