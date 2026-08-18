# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 2180_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2180_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 1-27 of the vulnerable file.

{% load i18n %}
{% if title %}
    {% if striptags %}
        {{ title|capfirst|striptags }}
    {% else %}
        {{ title|capfirst|safe }}
    {% endif %}
{% else %}
    {% if read_only %}
        {% if object_name %}
            {% blocktrans %}Details for {{ object_name }}: {{ object }}{% endblocktrans %}
        {% else %}
            {% blocktrans %}Details for: {{ object }}{% endblocktrans %}
        {% endif %}
    {% else %}
        {% if object %}
            {% if object_name %}
                {% blocktrans %}Edit {{ object_name }}:{% endblocktrans %} {% if not striptags %}<a href="{{ object.get_absolute_url }}">{% endif %}{{ object|capfirst }}{% if not striptags %}</a>{% endif %}
            {% else %}
                {% trans "Edit" %}: {% if not striptags %}<a href="{{ object.get_absolute_url }}">{% endif %}{{ object|capfirst }}{% if not striptags %}</a>{% endif %}
            {% endif %}
        {% else %}
            {% if object_name %}
                {% blocktrans %}Create new {{ object_name }}{% endblocktrans %}
            {% else %}
                {% trans "Create" %}
            {% endif %}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,10 +1,6 @@
 {% load i18n %}
 {% if title %}
-    {% if striptags %}
-        {{ title|capfirst|striptags }}
-    {% else %}
-        {{ title|capfirst|safe }}
-    {% endif %}
+    {{ title|capfirst }}
 {% else %}
     {% if read_only %}
         {% if object_name %}
@@ -15,9 +11,9 @@
     {% else %}
         {% if object %}
             {% if object_name %}
-                {% blocktrans %}Edit {{ object_name }}:{% endblocktrans %} {% if not striptags %}<a href="{{ object.get_absolute_url }}">{% endif %}{{ object|capfirst }}{% if not striptags %}</a>{% endif %}
+                {% blocktrans with object as object and object_name as object_name %}Edit {{ object_name }}: {{ object }}{% endblocktrans %}
             {% else %}
-                {% trans "Edit" %}: {% if not striptags %}<a href="{{ object.get_absolute_url }}">{% endif %}{{ object|capfirst }}{% if not striptags %}</a>{% endif %}
+                {% blocktrans with object as object %}Edit: {{ object }}{% endblocktrans %}
             {% endif %}
         {% else %}
             {% if object_name %}
@@ -25,6 +21,6 @@
             {% else %}
                 {% trans "Create" %}
             {% endif %}
-        {% endif %}                
+        {% endif %}
     {% endif %}
 {% endif %}
```
