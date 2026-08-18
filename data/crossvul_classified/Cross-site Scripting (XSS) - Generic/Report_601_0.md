# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 601_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `601_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 1-20 of the vulnerable file.

{% extends 'layouts/message.html' %}

{% block base %}
  <div class="container narrow card">
    <div class="container" id="header">
      <div class="col-1-1 header success">
        <i class="ion ion-thumbsup"></i>
      </div>
    </div>

    <div class="container">
      <div class="col-1-1">
        <h1>Form submitted successfully</h1>
        {% if request.args.get('next') %}
          <a href="{{ request.args.get('next') }}" class="button" style="margin-top: 1em;">Return to original site</a>
        {% endif %}
      </div>
    </div>
  </div>
{% endblock base %}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,9 +11,6 @@
     <div class="container">
       <div class="col-1-1">
         <h1>Form submitted successfully</h1>
-        {% if request.args.get('next') %}
-          <a href="{{ request.args.get('next') }}" class="button" style="margin-top: 1em;">Return to original site</a>
-        {% endif %}
       </div>
     </div>
   </div>
```
