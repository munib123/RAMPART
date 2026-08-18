# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 2180_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2180_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 1-40 of the vulnerable file.

{% load i18n %}
{% load attribute_tags %}
{% load pagination_tags %}
{% load navigation_tags %}
{% load non_breakable %}
{% load variable_tags %}
{% load main_settings_tags %}
{% load multiselect_tags %}

{% get_main_setting "DISABLE_ICONS" as disable_icons %}

{% if side_bar %}
    <div class="block">
    <h3>
        {{ title|capfirst }}
    </h3>
    <div class="content">
        <p>
{% else %}    
    {% autopaginate object_list %} 
    <div class="content">
    <h2 class="title">
        {% ifnotequal page_obj.paginator.num_pages 1 %}
            {% blocktrans with page_obj.start_index as start and page_obj.end_index as end and page_obj.paginator.object_list|length as total and page_obj.number as page_number and page_obj.paginator.num_pages as total_pages %}List of {{ title }} ({{ start }} - {{ end }} out of {{ total }}) (Page {{ page_number }} of {{ total_pages }}){% endblocktrans %}
        {% else %}
            {% blocktrans with page_obj.paginator.object_list|length as total %}List of {{ title }} ({{ total }}){% endblocktrans %}
        {% endifnotequal %}
    </h2>

    <div class="inner">
{% endif %}

        <form action="{% url multi_object_action_view %}" class="form multi_select" method="get">

            {% if object_list %}
                {% if multi_select or multi_select_as_buttons %}
                    {% if multi_select_as_buttons %}
                        {% get_multi_item_links as multi_item_links %}
                        <div class="group navform wat-cf" style="margin-bottom: 0px;">
                        {% for link in multi_item_links %}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,8 +16,8 @@
     </h3>
     <div class="content">
         <p>
-{% else %}    
-    {% autopaginate object_list %} 
+{% else %}
+    {% autopaginate object_list %}
     <div class="content">
     <h2 class="title">
         {% ifnotequal page_obj.paginator.num_pages 1 %}
@@ -53,9 +53,9 @@
                             </button>
                         </div>
                     {% endif %}
-                {% endif %}          
-            {% endif %}          
-        
+                {% endif %}
+            {% endif %}
+
             {% if scrollable_content %}
                 <div style="border: 1px solid; height: {{ scrollable_content_height }}; overflow: auto;">
             {% endif %}
@@ -78,11 +78,11 @@
 
                             {% for column in object_list.0|get_model_list_columns %}
                                 <th>{{ column.name|capfirst }}</th>
-                            {% endfor %}            
+                            {% endfor %}
 
                             {% for column in extra_columns %}
                                 <th>{{ column.name|capfirst }}</th>
-                            {% endfor %}        
+                            {% endfor %}
 
                             {% if not hide_links %}
                                 <th class="">&nbsp;</th>
@@ -91,7 +91,7 @@
                     {% endif %}
                     {% for object in object_list %}
                         <tr class="{% cycle 'odd' 'even2' %}">
-                        {% if multi_select or multi_select_as_buttons %}    
+                        {% if multi_select or multi_select_as_buttons %}
                             <td>
                             {% if multi_select_item_properties %}
                                 <input type="checkbox" class="checkbox" name="properties_{{ object|get_encoded_parameter:multi_select_item_properties }}" value="" />
@@ -117,7 +117,7 @@
                             {% else %}
                                 <td>{{ object|object_property:column.attribute }}</td>
                             {% endif %}
-                        {% endfor %}                        
+                        {% endfor %}
                         {% if not hide_columns %}
                             {% for column in object|get_model_list_columns %}
                                 <td>{{ object|object_property:column.attribute }}</td>
@@ -149,15 +149,15 @@
                             {% endif %}
                         </tr>
                     {% empty %}
-                        <tr><td colspan=99 class="tc">{% blocktrans with title|striptags as stripped_title %}There are no {{ stripped_title }}{% endblocktrans %}</td></tr>
+                        <tr><td colspan=99 class="tc">{% blocktrans with title as title %}There are no {{ title }}{% endblocktrans %}</td></tr>
                     {% endfor %}
                 </tbody>
             </table>
-            
+
             {% if scrollable_content %}
-                </div>            
-            {% endif %}            
-            
+                </div>
+            {% endif %}
+
             {% if object_list %}
                 {% if multi_select or multi_select_as_buttons %}
                     {% if multi_select_as_buttons %}
@@ -179,13 +179,13 @@
                             </button>
                         </div>
                     {% endif %}
-                {% endif %}  
-            {% endif %}  
+                {% endif %}
+            {% endif %}
         </form>
         {% paginate %}
-        
+
         {% if side_bar %}
             </p>
-        {% endif %} 
+        {% endif %}
     </div>
 </div>
```
