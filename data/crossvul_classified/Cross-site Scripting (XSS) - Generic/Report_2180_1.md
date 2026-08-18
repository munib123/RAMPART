# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 2180_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2180_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 1-25 of the vulnerable file.

{% extends "base.html" %}
{% load i18n %}
{% load subtemplates_tags %}

{% block title %} :: {% with "true" as read_only %}{% with "true" as striptags %}{% include "calculate_form_title.html" %}{% endwith %}{% endwith %}{% endblock %}

{% block sidebar %}
    {% for subtemplate in sidebar_subtemplates %}
        <div class="generic_subform">
            {% include subtemplate %}
        </div>        
    {% endfor %}
  
    {% for subtemplate in sidebar_subtemplates_list %}
        {% with "true" as side_bar %}
            {% if subtemplate.form %}
                {% render_subtemplate subtemplate.name subtemplate.context as rendered_subtemplate %}
                {% with "true" as read_only %}
                    <div class="generic_subform">
                        {{ rendered_subtemplate }}
                    </div>
                {% endwith %}
            {% else %}
                {% render_subtemplate subtemplate.name subtemplate.context as rendered_subtemplate %}
                {{ rendered_subtemplate }}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,15 +2,15 @@
 {% load i18n %}
 {% load subtemplates_tags %}
 
-{% block title %} :: {% with "true" as read_only %}{% with "true" as striptags %}{% include "calculate_form_title.html" %}{% endwith %}{% endwith %}{% endblock %}
+{% block title %} :: {% with "true" as read_only %}{% include "calculate_form_title.html" %}{% endwith %}{% endblock %}
 
 {% block sidebar %}
     {% for subtemplate in sidebar_subtemplates %}
         <div class="generic_subform">
             {% include subtemplate %}
-        </div>        
+        </div>
     {% endfor %}
-  
+
     {% for subtemplate in sidebar_subtemplates_list %}
         {% with "true" as side_bar %}
             {% if subtemplate.form %}
@@ -26,18 +26,18 @@
             {% endif %}
                 </div>
                 {% if subtemplate.grid_clear or not subtemplate.grid %}
-                    <div class=""></div> 
+                    <div class=""></div>
             {% endif %}
         {% endwith %}
-    {% endfor %}     
+    {% endfor %}
 {% endblock %}
 
 {% block stylesheets %}
     <style type="text/css">
-        #subform form  textarea, 
+        #subform form  textarea,
         #subform form  select option,
-        #subform form  input, 
-        #subform form  select, 
+        #subform form  input,
+        #subform form  select,
         #subform form  input { background: none; color: black; border: none; }
     </style>
 {% endblock %}
@@ -51,14 +51,14 @@
                 </div>
             </div>
             {% if grid_clear or not grid %}
-                <div class=""></div> 
+                <div class=""></div>
             {% endif %}
         {% endwith %}
     {% endif %}
-    
+
     <div class="container_12">
         {% for subtemplate in subtemplates_list %}
-            <div class="grid_{{ subtemplate.grid|default:12 }}">       
+            <div class="grid_{{ subtemplate.grid|default:12 }}">
                 {% with "true" as read_only %}
                     {% render_subtemplate subtemplate.name subtemplate.context as rendered_subtemplate %}
                     <div class="generic_subform">
@@ -67,10 +67,10 @@
                 {% endwith %}
             </div>
             {% if subtemplate.grid_clear or not subtemplate.grid %}
-                <div class="clear"></div> 
+                <div class="clear"></div>
             {% endif %}
          {% endfor %}
-    </div>    
-    
+    </div>
+
 {% endblock %}
 
```
