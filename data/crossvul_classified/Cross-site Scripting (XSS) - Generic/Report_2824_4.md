# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2824_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2824_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 84-124 of the vulnerable file.

     * @return {Ext.tree.TreeNode}
     */
    getActiveNode: function() {
        return this.ctxNode || this.getSelectionModel().getSelectedNode();
    },
    
    /**
     * updates the phone tree panel after an crud action and on load
     */
    updateTree: function() {
        // remove all children first
        var rootNode = this.getRootNode();
        rootNode.eachChild(function(child) {
            this.removeChild(child);
        });

        // add phones from store to tree menu
        this.store.each(function(record) {
            var label = (record.data.description == '') 
               ? record.data.macaddress 
               : Ext.util.Format.ellipsis(record.data.description, 30);
            var node = new Ext.tree.TreeNode({
                id: record.id,
                record: record,
                text: label,
                iconCls: 'PhoneIconCls',
                qtip: Tine.Tinebase.common.doubleEncode(record.data.description),
                leaf: true
            });
            rootNode.appendChild(node);
        }, this);
    },

    /**
     * @see Ext.Component
     */
    getState: function() {
        var root = this.getRootNode();
        
        var state = {
            selected: this.grid.ctxNode ? this.grid.ctxNode.id : null
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -101,13 +101,13 @@
         this.store.each(function(record) {
             var label = (record.data.description == '') 
                ? record.data.macaddress 
-               : Ext.util.Format.ellipsis(record.data.description, 30);
+               : Ext.util.Format.ellipsis(Ext.util.Format.htmlEncode(record.data.description), 30);
             var node = new Ext.tree.TreeNode({
                 id: record.id,
                 record: record,
                 text: label,
                 iconCls: 'PhoneIconCls',
-                qtip: Tine.Tinebase.common.doubleEncode(record.data.description),
+                qtip: Ext.util.Format.htmlEncode(record.data.description),
                 leaf: true
             });
             rootNode.appendChild(node);
```
