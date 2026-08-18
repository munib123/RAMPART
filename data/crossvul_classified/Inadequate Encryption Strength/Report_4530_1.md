# CrossVul Fix Pair: Inadequate Encryption Strength in html
**Pair ID:** 4530_1
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4530_1`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```html
Lines 1-36 of the vulnerable file.

{% extends "user_sessions/_base.html" %}
{% load user_sessions i18n %}

{% block content %}
  {% trans "<em>unknown on unknown</em>" as unknown_on_unknown %}
  {% trans "<em>unknown</em>" as unknown %}

  <h1>{% trans "Active Sessions" %}</h1>

  <table class="table">
    <thead>
      <tr>
        <th>{% trans "Location" %}</th>
        <th>{% trans "Device" %}</th>
        <th>{% trans "Last Activity" %}</th>
        <th>{% trans "End Session" %}</th>
      </tr>
    </thead>
    {% for object in object_list %}
      <tr {% if object.session_key == session_key %}class="active"{% endif %}>
        <td>{{ object.ip|location|default_if_none:unknown|safe }} <small>({{ object.ip }})</small></td>
        <td>{{ object.user_agent|device|default_if_none:unknown_on_unknown|safe }}</td>
        <td>
          {% if object.session_key == session_key %}
            {% blocktrans with time=object.last_activity|timesince %}{{ time }} ago (this session){% endblocktrans %}
          {% else %}
            {% blocktrans with time=object.last_activity|timesince %}{{ time }} ago{% endblocktrans %}
          {% endif %}
        </td>
        <td>
          <form method="post" action="{% url 'user_sessions:session_delete' object.pk %}">
            {% csrf_token %}
            {% if object.session_key == session_key %}
              <button type="submit" class="btn btn-xs btn-link">{% trans "End Session" %}</button>
            {% else %}
              <button type="submit" class="btn btn-xs btn-warning">{% trans "End Session" %}</button>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,7 +13,6 @@
         <th>{% trans "Location" %}</th>
         <th>{% trans "Device" %}</th>
         <th>{% trans "Last Activity" %}</th>
-        <th>{% trans "End Session" %}</th>
       </tr>
     </thead>
     {% for object in object_list %}
@@ -26,16 +25,6 @@
           {% else %}
             {% blocktrans with time=object.last_activity|timesince %}{{ time }} ago{% endblocktrans %}
           {% endif %}
-        </td>
-        <td>
-          <form method="post" action="{% url 'user_sessions:session_delete' object.pk %}">
-            {% csrf_token %}
-            {% if object.session_key == session_key %}
-              <button type="submit" class="btn btn-xs btn-link">{% trans "End Session" %}</button>
-            {% else %}
-              <button type="submit" class="btn btn-xs btn-warning">{% trans "End Session" %}</button>
-            {% endif %}
-          </form>
         </td>
       </tr>
     {% endfor %}
```
