# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 4097_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4097_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-24 of the vulnerable file.

from collections import OrderedDict

import django.forms
from django.utils.translation import gettext_lazy as _

from wagtail.admin.forms import WagtailAdminPageForm
from wagtail.contrib.forms.utils import get_field_clean_name


class BaseForm(django.forms.Form):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', '')

        self.user = kwargs.pop('user', None)
        self.page = kwargs.pop('page', None)

        super().__init__(*args, **kwargs)


class FormBuilder:
    def __init__(self, fields):
        self.fields = fields

    def create_singleline_field(self, field, options):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,8 @@
 from collections import OrderedDict
 
 import django.forms
+from django.conf import settings
+from django.utils.html import conditional_escape
 from django.utils.translation import gettext_lazy as _
 
 from wagtail.admin.forms import WagtailAdminPageForm
@@ -114,7 +116,10 @@
     def get_field_options(self, field):
         options = {}
         options['label'] = field.label
-        options['help_text'] = field.help_text
+        if getattr(settings, 'WAGTAILFORMS_HELP_TEXT_ALLOW_HTML', False):
+            options['help_text'] = field.help_text
+        else:
+            options['help_text'] = conditional_escape(field.help_text)
         options['required'] = field.required
         options['initial'] = field.default_value
         return options
```
