# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 5730_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5730_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 288-328 of the vulnerable file.

        super(AdminTextInputWidget, self).__init__(attrs=final_attrs)

class AdminEmailInputWidget(forms.EmailInput):
    def __init__(self, attrs=None):
        final_attrs = {'class': 'vTextField'}
        if attrs is not None:
            final_attrs.update(attrs)
        super(AdminEmailInputWidget, self).__init__(attrs=final_attrs)

class AdminURLFieldWidget(forms.URLInput):
    def __init__(self, attrs=None):
        final_attrs = {'class': 'vURLField'}
        if attrs is not None:
            final_attrs.update(attrs)
        super(AdminURLFieldWidget, self).__init__(attrs=final_attrs)

    def render(self, name, value, attrs=None):
        html = super(AdminURLFieldWidget, self).render(name, value, attrs)
        if value:
            value = force_text(self._format_value(value))
            final_attrs = {'href': mark_safe(smart_urlquote(value))}
            html = format_html(
                '<p class="url">{0} <a {1}>{2}</a><br />{3} {4}</p>',
                _('Currently:'), flatatt(final_attrs), value,
                _('Change:'), html
            )
        return html


class AdminIntegerFieldWidget(forms.TextInput):
    class_name = 'vIntegerField'

    def __init__(self, attrs=None):
        final_attrs = {'class': self.class_name}
        if attrs is not None:
            final_attrs.update(attrs)
        super(AdminIntegerFieldWidget, self).__init__(attrs=final_attrs)

class AdminBigIntegerFieldWidget(AdminIntegerFieldWidget):
    class_name = 'vBigIntegerField'

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -305,9 +305,9 @@
         html = super(AdminURLFieldWidget, self).render(name, value, attrs)
         if value:
             value = force_text(self._format_value(value))
-            final_attrs = {'href': mark_safe(smart_urlquote(value))}
+            final_attrs = {'href': smart_urlquote(value)}
             html = format_html(
-                '<p class="url">{0} <a {1}>{2}</a><br />{3} {4}</p>',
+                '<p class="url">{0} <a{1}>{2}</a><br />{3} {4}</p>',
                 _('Currently:'), flatatt(final_attrs), value,
                 _('Change:'), html
             )
```
