# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 2186_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2186_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 14-54 of the vulnerable file.

#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from __future__ import unicode_literals

import json

from django import template
from django.core.serializers import serialize
from django.db.models.query import QuerySet
from django.utils import six
from django.utils.safestring import mark_safe

from djblets.util.serializers import DjbletsJSONEncoder


register = template.Library()


@register.simple_tag
def form_dialog_fields(form):
    """
    Translates a Django Form object into a JavaScript list of fields.
    The resulting list of fields can be used to represent the form
    dynamically.
    """
    s = ''

    for field in form:
        s += "{ name: '%s', " % field.name

        if field.is_hidden:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,12 +31,19 @@
 from django.core.serializers import serialize
 from django.db.models.query import QuerySet
 from django.utils import six
+from django.utils.encoding import force_text
 from django.utils.safestring import mark_safe
 
 from djblets.util.serializers import DjbletsJSONEncoder
 
 
 register = template.Library()
+
+_safe_js_escapes = {
+    ord('&'): '\\u0026',
+    ord('<'): '\\u003C',
+    ord('>'): '\\u003E',
+}
 
 
 @register.simple_tag
@@ -75,7 +82,7 @@
     else:
         result = json.dumps(value, indent=indent, cls=DjbletsJSONEncoder)
 
-    return mark_safe(result)
+    return mark_safe(force_text(result).translate(_safe_js_escapes))
 
 
 @register.filter
```
