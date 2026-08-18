# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in html
**Pair ID:** 1654_3
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1654_3`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```html
Lines 13-54 of the vulnerable file.

		<span id="move-target-{{ page.id }}" class="move-target-container" >
			{% if not CMS_PERMISSION or has_add_permission or has_add_page_permission %}{% spaceless %}
				{# if permissions not enabled, user user haves global can_add page #}
					{% if has_add_on_same_level_permission %}
						<a href="#" class="move-target left" title="{% trans "insert above" %}">↑</a>
						<a href="#" class="move-target right" title="{% trans "insert below" %}">↓</a>
					{% endif %}
				<a href="#" class="move-target last-child" title="{% trans "insert inside" %}">↘</a>
			{% endspaceless %}{% endif %}
		</span>

		{% if page.soft_root or page.is_home %}<div class="col-softroot"><span class="icon softroot-icon" title="{% if page.soft_root %}{% trans 'softroot' %}{% else %}{% trans 'home' %}{% endif %}"></span></div>{% endif %}
		{% if page.application_urls %}<div class="col-apphook"><a href="{{ page.id }}/advanced-settings/"><span class="icon apphook-icon" title="{% blocktrans with page.application_urls as apphook%}Application: {{ apphook }}{% endblocktrans %}"></span></a></div>{% endif %}
		{% for lang in site_languages %}
		<div class="col-language">
			{% if has_change_permission %}
				<a href="{% if lang in page.languages %}./{{ page.id }}/{{ lang }}/preview/{% else %}./{{ page.id }}/?language={{ lang }}{% endif %}" class="trigger-tooltip"{% if lang in page.languages %} target="_top"{% endif %} title="{% blocktrans with lang|upper as language %}Edit this page in {{ language }} {% endblocktrans %}">{% tree_publish_row page lang %}</a>
				{% if lang in page.languages %}
				<div class="language-tooltip" hidden="hidden">
					{% trans "Pick an action:" %}
					<a href="./{{ page.id }}/{{ lang }}/unpublish/?redirect_language={{ preview_language }}&redirect_page_id={{ request.GET.page_id }}">{% trans "Unpublish" %}</a>
					<a href="./{{ page.id }}/{{ lang }}/publish/?redirect_language={{ preview_language }}&redirect_page_id={{ request.GET.page_id }}">{% trans "Publish" %}</a>
				</div>
				{% endif %}
			{% else %}
				{% tree_publish_row page lang %}
			{% endif %}
		</div>
		{% endfor %}
		<div class="col-navigation" title="{% if page.in_navigation %}{% trans "in menu" %}{% else %}{% trans "not in menu" %}{% endif %}">
			<label>
				<img alt="{{ page.in_navigation|yesno:"True,False" }}" src="{% cms_admin_icon_base %}icon-{{ page.in_navigation|yesno:"yes,no" }}.gif" />
				{% if has_change_permission %}<input type="checkbox" class="navigation-checkbox" name="navigation-{{ page.id }}" {% if page.in_navigation %}checked="checked"{% endif %} value="{{ page.in_navigation|yesno:"1,0" }}" />{% endif %}
			</label>
		</div>
		<div class="col-actions">

			{% if has_change_permission %}
			<a class="edit" href="{{ url }}{{ page.id }}/" data-alt-class="advanced-settings" data-alt-href="{{ url }}{{ page.id }}/advanced-settings/" title="{% trans "Page settings (SHIFT-click for advanced settings)" %}"><span>{% trans "page settings" %}</span></a>
			{# <!--a href="{{ url }}{{ page.id }}/advanced-settings/" class="advanced-settings" title="{% trans "Advanced settings" %}"><span>{% trans "Advanced settings" %}</span></a--> #}
			<a href="#" class="copy" title="{% trans "Copy" %}" id="copy-link-{{ page.id }}"><span>{% trans "copy" %}</span></a>{% endif %}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,8 +30,8 @@
 				{% if lang in page.languages %}
 				<div class="language-tooltip" hidden="hidden">
 					{% trans "Pick an action:" %}
-					<a href="./{{ page.id }}/{{ lang }}/unpublish/?redirect_language={{ preview_language }}&redirect_page_id={{ request.GET.page_id }}">{% trans "Unpublish" %}</a>
-					<a href="./{{ page.id }}/{{ lang }}/publish/?redirect_language={{ preview_language }}&redirect_page_id={{ request.GET.page_id }}">{% trans "Publish" %}</a>
+					<a href="./{{ page.id }}/{{ lang }}/unpublish/?redirect_language={{ preview_language }}&redirect_page_id={{ request.GET.page_id }}" class="js-ajax-submit">{% trans "Unpublish" %}</a>
+					<a href="./{{ page.id }}/{{ lang }}/publish/?redirect_language={{ preview_language }}&redirect_page_id={{ request.GET.page_id }}" class="js-ajax-submit">{% trans "Publish" %}</a>
 				</div>
 				{% endif %}
 			{% else %}
```
