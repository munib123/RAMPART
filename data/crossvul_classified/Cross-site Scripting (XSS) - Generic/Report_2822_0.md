# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2822_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2822_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 176-216 of the vulnerable file.

                                    xtype: 'displayfield',
                                    name: 'isIndexed',
                                    hideLabel: true,
                                    fieldClass: 'x-ux-displayfield-text',
                                    width: 10,
                                    setValue: function(value) {
                                        var string, color, html = '';
                                        if (Tine.Tinebase.configManager.get('filesystem.index_content', 'Tinebase') && me.record.get('type') == 'file') {
                                            string = value ? me.app.i18n._('Indexed') : me.app.i18n._('Not yet indexed');
                                            color = value ? 'green' : 'yellow';
                                            html = ['<span style="color:', color, ' !important;" qtip="',string, '">&bull;</span>'].join('');
                                        }

                                        this.setRawValue(html);
                                    }
                                }, {
                                    xtype: 'displayfield',
                                    name: 'path',
                                    hideLabel: true,
                                    fieldClass: 'x-ux-displayfield-text',
                                    columnWidth: 1
                                }],[
                                Tine.widgets.form.RecordPickerManager.get('Addressbook', 'Contact', {
                                    userOnly: true,
                                    useAccountRecord: true,
                                    blurOnSelect: true,
                                    fieldLabel: this.app.i18n._('Created By'),
                                    name: 'created_by'
                                }), {
                                    fieldLabel: this.app.i18n._('Creation Time'),
                                    name: 'creation_time',
                                    xtype: 'datefield'
                                }
                                ],[
                                Tine.widgets.form.RecordPickerManager.get('Addressbook', 'Contact', {
                                    userOnly: true,
                                    useAccountRecord: true,
                                    blurOnSelect: true,
                                    fieldLabel: this.app.i18n._('Modified By'),
                                    name: 'last_modified_by'
                                }), {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -193,6 +193,7 @@
                                     name: 'path',
                                     hideLabel: true,
                                     fieldClass: 'x-ux-displayfield-text',
+                                    htmlEncode: true,
                                     columnWidth: 1
                                 }],[
                                 Tine.widgets.form.RecordPickerManager.get('Addressbook', 'Contact', {
```
