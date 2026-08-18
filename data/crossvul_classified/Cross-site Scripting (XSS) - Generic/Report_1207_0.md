# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1207_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1207_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 85-125 of the vulnerable file.

            {name: 'editor', persist: false},
            {name: 'key', allowBlank: false},
            {name: 'creationDate', type: 'date', convert: dateConverter, persist: false},
            {name: 'modificationDate', type: 'date', convert: dateConverter, persist: false}
        ];

        var typesColumns = [
            {text: t("key"), sortable: true, dataIndex: 'key', editable: false, filter: 'string'}
        ];

        for (var i = 0; i < languages.length; i++) {
            readerFields.push({name: "_" + languages[i]});

            var columnConfig = {
                cls: "x-column-header_" + languages[i].toLowerCase(),
                text: pimcore.available_languages[languages[i]],
                sortable: true,
                dataIndex: "_" + languages[i],
                filter: 'string',
                getEditor: this.getCellEditor.bind(this, languages[i]),
                id: "translation_column_" + this.translationType + "_" + languages[i].toLowerCase()
            };
            if (applyInitialSettings) {
                var hidden = i >= maxLanguages;
                columnConfig.hidden = hidden;
            }

            typesColumns.push(columnConfig);
        }

        if (showInfo) {
            pimcore.helpers.showNotification(t("info"), t("there_are_more_columns"), null, null, 2000);
        }

        var dateRenderer = function (d) {
            var date = new Date(d * 1000);
            return Ext.Date.format(date, "Y-m-d H:i:s");
        };
        typesColumns.push({
            text: t("creationDate"), sortable: true, dataIndex: 'creationDate', editable: false
            , renderer: dateRenderer, filter: 'date'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -102,6 +102,9 @@
                 dataIndex: "_" + languages[i],
                 filter: 'string',
                 getEditor: this.getCellEditor.bind(this, languages[i]),
+                renderer: function (text) {
+                    return replace_html_event_attributes(strip_tags(text, 'div,span,b,strong,em,i,small,sup,sub,p'));
+                },
                 id: "translation_column_" + this.translationType + "_" + languages[i].toLowerCase()
             };
             if (applyInitialSettings) {
```
