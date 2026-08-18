# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2824_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2824_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 236-276 of the vulnerable file.

            application: this.app.appName,
            owner: owner,
            filter: [
                     {field: 'path', operator:'equals', value: newPath},
                     {field: 'type', operator:'equals', value: 'folder'}
                     ],
            paging: {dir: 'ASC', limit: 50, sort: 'name', start: 0}
        };
        
        return params;
    },
    
    onBeforeCreateNode: function(attr) {
        Tine.Filemanager.NodeTreePanel.superclass.onBeforeCreateNode.apply(this, arguments);
        
        attr.leaf = false;
        
        if(attr.name && typeof attr.name == 'object') {
            Ext.apply(attr, {
                text: Ext.util.Format.htmlEncode(attr.name.name),
                qtip: Tine.Tinebase.common.doubleEncode(attr.name.name)
            });
        }
        
        // copy 'real' data to a node record NOTE: not a full record as we have no record reader here
        var nodeData = Ext.copyTo({}, attr, Tine.Filemanager.Model.Node.getFieldNames());
        attr.nodeRecord = new Tine.Filemanager.Model.Node(nodeData);
    },
    
    /**
     * initiates tree context menues
     * 
     * @private
     */
    initContextMenu: function() {
        
        this.contextMenuUserFolder = Tine.widgets.tree.ContextMenu.getMenu({
            nodeName: this.app.i18n._(this.containerName),
            actions: ['add', 'reload', 'delete', 'rename', 'properties'],
            scope: this,
            backend: 'Filemanager',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -253,10 +253,10 @@
         if(attr.name && typeof attr.name == 'object') {
             Ext.apply(attr, {
                 text: Ext.util.Format.htmlEncode(attr.name.name),
-                qtip: Tine.Tinebase.common.doubleEncode(attr.name.name)
+                qtip: Ext.util.Format.htmlEncode(attr.name.name)
             });
         }
-        
+
         // copy 'real' data to a node record NOTE: not a full record as we have no record reader here
         var nodeData = Ext.copyTo({}, attr, Tine.Filemanager.Model.Node.getFieldNames());
         attr.nodeRecord = new Tine.Filemanager.Model.Node(nodeData);
@@ -577,13 +577,13 @@
         var newNodeRecord = new Tine.Filemanager.Model.Node(nodeData);
         
         var newNode = new Ext.tree.AsyncTreeNode({
-            text: nodeName,
+            text: Ext.util.Format.htmlEncode(nodeName),
             path: nodeData.path,
             name: nodeData.name,
             nodeRecord: newNodeRecord,
             account_grants: nodeData.account_grants,
             id: nodeData.id
-        })
+        });
         
         newNode.attributes.nodeRecord.beginEdit();
         newNode.attributes.nodeRecord.set('path', nodeData.path);
```
