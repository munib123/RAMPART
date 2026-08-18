# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 3890_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3890_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 12-52 of the vulnerable file.

from django.core.serializers.json import DjangoJSONEncoder
from django.db import models
from django.shortcuts import redirect, render
from modelcluster.contrib.taggit import ClusterTaggableManager
from modelcluster.fields import ParentalKey, ParentalManyToManyField
from modelcluster.models import ClusterableModel
from taggit.managers import TaggableManager
from taggit.models import TaggedItemBase

from wagtail.admin.edit_handlers import (
    FieldPanel, InlinePanel, MultiFieldPanel, ObjectList, PageChooserPanel, StreamFieldPanel,
    TabbedInterface)
from wagtail.admin.forms import WagtailAdminPageForm
from wagtail.admin.mail import send_mail
from wagtail.contrib.forms.forms import FormBuilder
from wagtail.contrib.forms.models import (
    FORM_FIELD_CHOICES, AbstractEmailForm, AbstractFormField, AbstractFormSubmission)
from wagtail.contrib.settings.models import BaseSetting, register_setting
from wagtail.contrib.sitemaps import Sitemap
from wagtail.contrib.table_block.blocks import TableBlock
from wagtail.core.blocks import CharBlock, RichTextBlock, StructBlock
from wagtail.core.fields import RichTextField, StreamField
from wagtail.core.models import Orderable, Page, PageManager, PageQuerySet
from wagtail.documents.edit_handlers import DocumentChooserPanel
from wagtail.documents.models import AbstractDocument, Document
from wagtail.images.blocks import ImageChooserBlock
from wagtail.images.edit_handlers import ImageChooserPanel
from wagtail.images.models import AbstractImage, AbstractRendition, Image
from wagtail.search import index
from wagtail.snippets.edit_handlers import SnippetChooserPanel
from wagtail.snippets.models import register_snippet
from wagtail.utils.decorators import cached_classmethod

from .forms import FormClassAdditionalFieldPageForm, ValidatedPageForm
from .views import CustomSubmissionsListView

EVENT_AUDIENCE_CHOICES = (
    ('public', "Public"),
    ('private', "Private"),
)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,7 +29,7 @@
 from wagtail.contrib.settings.models import BaseSetting, register_setting
 from wagtail.contrib.sitemaps import Sitemap
 from wagtail.contrib.table_block.blocks import TableBlock
-from wagtail.core.blocks import CharBlock, RichTextBlock, StructBlock
+from wagtail.core.blocks import CharBlock, RawHTMLBlock, RichTextBlock, StructBlock
 from wagtail.core.fields import RichTextField, StreamField
 from wagtail.core.models import Orderable, Page, PageManager, PageQuerySet
 from wagtail.documents.edit_handlers import DocumentChooserPanel
@@ -972,6 +972,7 @@
             ('name', CharBlock()),
             ('price', CharBlock()),
         ])),
+        ('raw_html', RawHTMLBlock()),
     ])
 
     api_fields = ('body',)
```
