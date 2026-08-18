# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 5191_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5191_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 71-111 of the vulnerable file.

            'fields': ('date', 'section')
        })
    )


class ChapterInline(admin.TabularInline):
    model = Chapter


class ChapterXtra1Admin(admin.ModelAdmin):
    list_filter = ('chap',
                   'chap__title',
                   'chap__book',
                   'chap__book__name',
                   'chap__book__promo',
                   'chap__book__promo__name',)


class ArticleAdmin(admin.ModelAdmin):
    list_display = ('content', 'date', callable_year, 'model_year',
                    'modeladmin_year', 'model_year_reversed')
    list_filter = ('date', 'section')
    view_on_site = False
    fieldsets = (
        ('Some fields', {
            'classes': ('collapse',),
            'fields': ('title', 'content')
        }),
        ('Some other fields', {
            'classes': ('wide',),
            'fields': ('date', 'section', 'sub_section')
        })
    )

    def changelist_view(self, request):
        "Test that extra_context works"
        return super(ArticleAdmin, self).changelist_view(
            request, extra_context={
                'extra_var': 'Hello!'
            }
        )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,7 +88,8 @@
 
 class ArticleAdmin(admin.ModelAdmin):
     list_display = ('content', 'date', callable_year, 'model_year',
-                    'modeladmin_year', 'model_year_reversed')
+                    'modeladmin_year', 'model_year_reversed', 'section')
+    list_editable = ('section',)
     list_filter = ('date', 'section')
     view_on_site = False
     fieldsets = (
```
