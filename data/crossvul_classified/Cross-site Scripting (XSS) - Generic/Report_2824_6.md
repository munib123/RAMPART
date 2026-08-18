# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2824_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2824_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 105-145 of the vulnerable file.

            selModel: rowSelectionModel,
            border: false,                  
            //autoExpandColumn: 'note',
            //enableColLock:false,
            //autoHeight: true,
            viewConfig: {
                autoFill: true,
                forceFit: true,
                ignoreAdd: true,
                autoScroll: true
            }  
        });
        
        return gridPanel;
    },

    noteRenderer: function(note) {
        var recordClass = Tine.Tinebase.data.RecordMgr.get(this.record_model),
            app = Tine.Tinebase.appMgr.get(this.app);

        if (recordClass) {
            Ext.each(recordClass.getFieldDefinitions(), function(field) {
                if (field.label) {
                    note = String(note).replace(field.name, '<br>' + app.i18n._hidden(field.label));
                    //map[field.name] = '<br>' + this.app.i18n._hidden(field.label);
                }
            }, this);
        }

        return note;
    },

    /**
     * init the contacts json grid store
     */
    initStore: function () {

        this.store = new Ext.data.JsonStore({
            id: 'id',
            autoLoad: false,
            root: 'results',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -122,6 +122,8 @@
         var recordClass = Tine.Tinebase.data.RecordMgr.get(this.record_model),
             app = Tine.Tinebase.appMgr.get(this.app);
 
+        note = Ext.util.Format.htmlEncode(note);
+        
         if (recordClass) {
             Ext.each(recordClass.getFieldDefinitions(), function(field) {
                 if (field.label) {
```
