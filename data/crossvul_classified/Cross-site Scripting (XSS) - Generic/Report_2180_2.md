# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 2180_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2180_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 1-24 of the vulnerable file.

{% extends "base.html" %}
{% load subtemplates_tags %}

{% block title %} :: {% with "true" as striptags %}{% include "calculate_form_title.html" %}{% endwith %}{% endblock %}

{% block sidebar %}
    {% for subtemplate in sidebar_subtemplates_list %}
        {% if subtemplate.form %}
            {% render_subtemplate subtemplate.name subtemplate.context as rendered_subtemplate %}
                <div class="generic_subform">
                    {{ rendered_subtemplate }}
                </div>
        {% else %}
            {% render_subtemplate subtemplate.name subtemplate.context as rendered_subtemplate %}
            {{ rendered_subtemplate }}
        {% endif %}
            {% if subtemplate.grid_clear or not subtemplate.grid %}
            {% endif %}
    {% endfor %}
{% endblock %}

{% block content %}
    {% if form %}
        <div class="generic_subform">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 {% extends "base.html" %}
 {% load subtemplates_tags %}
 
-{% block title %} :: {% with "true" as striptags %}{% include "calculate_form_title.html" %}{% endwith %}{% endblock %}
+{% block title %} :: {% include "calculate_form_title.html" %}{% endblock %}
 
 {% block sidebar %}
     {% for subtemplate in sidebar_subtemplates_list %}
@@ -25,10 +25,10 @@
             {% include "generic_form_subtemplate.html" %}
         </div>
     {% endif %}
-                             
+
 <div class="container_12">
     {% for subtemplate in subtemplates_list %}
-        <div class="grid_{{ subtemplate.grid|default:12 }}">       
+        <div class="grid_{{ subtemplate.grid|default:12 }}">
             {% if subtemplate.form %}
                 {% render_subtemplate subtemplate.name subtemplate.context as rendered_subtemplate %}
                     <div class="generic_subform">
@@ -40,7 +40,7 @@
             {% endif %}
         </div>
         {% if subtemplate.grid_clear or not subtemplate.grid %}
-            <div class="clear"></div> 
+            <div class="clear"></div>
         {% endif %}
      {% endfor %}
 </div>
```
