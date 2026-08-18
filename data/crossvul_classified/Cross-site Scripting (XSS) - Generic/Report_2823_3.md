# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2823_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2823_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 554-600 of the vulnerable file.

                
            }
        }, this);  
    },
    
    /**
     * delete selected files / folders
     * 
     * @param {Ext.Component} button
     * @param {Ext.EventObject} event
     */
    onDeleteRecords: function(button, event) {
        var app = this.app,
            nodeName = '',
            sm = app.getMainScreen().getCenterPanel().selectionModel,
            nodes = sm.getSelections();
        
        if(nodes && nodes.length) {
            for(var i=0; i<nodes.length; i++) {
                var currNodeData = nodes[i].data;
                
                if(typeof currNodeData.name == 'object') {
                    nodeName += currNodeData.name.name + '<br />';
                }
                else {
                    nodeName += currNodeData.name + '<br />';
                }
            }
        }
        
        this.conflictConfirmWin = Tine.widgets.dialog.FileListDialog.openWindow({
            modal: true,
            allowCancel: false,
            height: 180,
            width: 300,
            title: app.i18n._('Do you really want to delete the following files?'),
            text: nodeName,
            scope: this,
            handler: function(button){
                if (nodes && button == 'yes') {
                    this.store.remove(nodes);
                    this.pagingToolbar.refresh.disable();
                    Tine.Filemanager.fileRecordBackend.deleteItems(nodes);
                }
                
                for(var i=0; i<nodes.length; i++) {
                    var node = nodes[i];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -571,13 +571,10 @@
         if(nodes && nodes.length) {
             for(var i=0; i<nodes.length; i++) {
                 var currNodeData = nodes[i].data;
-                
-                if(typeof currNodeData.name == 'object') {
-                    nodeName += currNodeData.name.name + '<br />';
-                }
-                else {
-                    nodeName += currNodeData.name + '<br />';
-                }
+
+                nodeName += Ext.util.Format.htmlEncode(typeof currNodeData.name == 'object' ?
+                    currNodeData.name.name :
+                    currNodeData.name) + '<br />';
             }
         }
         
```
