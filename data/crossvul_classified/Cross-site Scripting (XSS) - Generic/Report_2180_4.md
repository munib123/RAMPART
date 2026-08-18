# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 2180_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2180_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 1-26 of the vulnerable file.

{% extends "base.html" %}
{% load i18n %}
{% load navigation_tags %}
{% load subtemplates_tags %}

{% block title %} :: {% blocktrans with title|striptags as stripped_title %}List of {{ stripped_title }}{% endblocktrans %}{% endblock %}
{#{% block secondary_links %}{{ secondary_links|safe }}{% endblock %}#}

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
     {% endfor %}

{% endblock %}

{% block content %}
    {% include "generic_list_horizontal_subtemplate.html" %}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,7 @@
 {% load navigation_tags %}
 {% load subtemplates_tags %}
 
-{% block title %} :: {% blocktrans with title|striptags as stripped_title %}List of {{ stripped_title }}{% endblocktrans %}{% endblock %}
+{% block title %} :: {% blocktrans with title as title %}List of {{ title }}{% endblocktrans %}{% endblock %}
 {#{% block secondary_links %}{{ secondary_links|safe }}{% endblock %}#}
 
 {% block sidebar %}
```
