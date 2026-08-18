# CrossVul Fix Pair: Data Processing Errors in javascript
**Pair ID:** 1441_0
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1441_0`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```javascript
Lines 60-102 of the vulnerable file.

                            }
                        });

                    editor.widgets.add('oembed',
                        {
                            draggable: false,
                            mask: true,
                            dialog: 'oembed',
                            allowedContent: {
                                div: {
                                    styles: 'text-align,float',
                                    attributes: '*',
                                    classes: editor.config.oembed_WrapperClass != null
                                        ? editor.config.oembed_WrapperClass
                                        : "embeddedContent"
                                },
                                'div(embeddedContent,oembed-provider-*) iframe': {
                                    attributes: '*'
                                },
                                'div(embeddedContent,oembed-provider-*) blockquote': {
                                    attributes: '*'
                                },
                                'div(embeddedContent,oembed-provider-*) script': {
                                    attributes: '*'
                                },
                                'div(embeddedContent,oembed-provider-*) embed': {
                                    attributes: '*'
                                }
                            },
                            template:
                                '<div class="' +
                                    (editor.config.oembed_WrapperClass != null
                                        ? editor.config.oembed_WrapperClass
                                        : "embeddedContent") +
                                    '">' +
                                    '</div>',
                            upcast: function(element) {
                                return element.name == 'div' &&
                                    element.hasClass(editor.config.oembed_WrapperClass != null
                                        ? editor.config.oembed_WrapperClass
                                        : "embeddedContent");
                            },
                            init: function() {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -77,9 +77,6 @@
                                     attributes: '*'
                                 },
                                 'div(embeddedContent,oembed-provider-*) blockquote': {
-                                    attributes: '*'
-                                },
-                                'div(embeddedContent,oembed-provider-*) script': {
                                     attributes: '*'
                                 },
                                 'div(embeddedContent,oembed-provider-*) embed': {
```
