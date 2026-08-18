# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 2188_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2188_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 8-48 of the vulnerable file.

# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
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

from django import template

from djblets.gravatars import (get_gravatar_url,
                               get_gravatar_url_for_email)
from djblets.util.decorators import basictag


register = template.Library()


@register.tag
@basictag(takes_context=True)
def gravatar(context, user, size=None):
    """
    Outputs the HTML for displaying a user's gravatar.

    This can take an optional size of the image (defaults to 80 if not
    specified).

    This is also influenced by the following settings:

        GRAVATAR_SIZE    - Default size for gravatars
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,6 +25,7 @@
 from __future__ import unicode_literals
 
 from django import template
+from django.utils.html import format_html
 
 from djblets.gravatars import (get_gravatar_url,
                                get_gravatar_url_for_email)
@@ -55,9 +56,10 @@
     url = get_gravatar_url(context['request'], user, size)
 
     if url:
-        return ('<img src="%s" width="%s" height="%s" alt="%s" '
-                '     class="gravatar"/>' %
-                (url, size, size, user.get_full_name() or user.username))
+        return format_html(
+            '<img src="{0}" width="{1}" height="{1}" alt="{2}" '
+            'class="gravatar"/>',
+            url, size, user.get_full_name() or user.username)
     else:
         return ''
 
```
