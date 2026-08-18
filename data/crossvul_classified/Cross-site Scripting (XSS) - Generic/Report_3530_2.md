# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 3530_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3530_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-27 of the vulnerable file.

from django import template
from django.conf import settings
from django.db.models import Q
from django.template import NodeList, TemplateSyntaxError
from django.template.loader import render_to_string
from django.utils import simplejson
from django.utils.translation import ugettext_lazy as _
from djblets.util.decorators import basictag, blocktag
from djblets.util.misc import get_object_or_none
from djblets.util.templatetags.djblets_utils import humanize_list

from reviewboard.accounts.models import Profile
from reviewboard.diffviewer.models import DiffSet
from reviewboard.reviews.models import Comment, Group, ReviewRequest, \
                                       ScreenshotComment


register = template.Library()


@register.tag
@blocktag
def forcomment(context, nodelist, filediff, review=None):
    """
    Loops over a list of comments beloning to a filediff.

    This will populate a special ``comment`` variable for use in the content.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,7 @@
 from django.template import NodeList, TemplateSyntaxError
 from django.template.loader import render_to_string
 from django.utils import simplejson
+from django.utils.html import escape
 from django.utils.translation import ugettext_lazy as _
 from djblets.util.decorators import basictag, blocktag
 from djblets.util.misc import get_object_or_none
@@ -126,7 +127,7 @@
 
             comment_dict.setdefault(key, []).append({
                 'comment_id': comment.id,
-                'text': comment.text,
+                'text': escape(comment.text),
                 'line': comment.first_line,
                 'num_lines': comment.num_lines,
                 'user': {
@@ -185,7 +186,7 @@
 
             comments.setdefault(position, []).append({
                 'id': comment.id,
-                'text': comment.text,
+                'text': escape(comment.text),
                 'user': {
                     'username': review.user.username,
                     'name': review.user.get_full_name() or review.user.username,
```
