# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2824_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2824_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 478-519 of the vulnerable file.

        }
    },

    /**
     * adopt attr
     * 
     * @param {Object} attr
     */
    onBeforeCreateNode: function(attr) {
        if (attr.accountDisplayName) {
            attr.name = attr.accountDisplayName;
            attr.path = '/personal/' + attr.accountId;
            attr.id = attr.accountId;
        }
        
        if (! attr.name && attr.path) {
            attr.name = Tine.Tinebase.container.path2name(attr.path, this.containerName, this.containersName);
        }
        
        Ext.applyIf(attr, {
            text: Ext.util.Format.htmlEncode(attr.name),
            qtip: Tine.Tinebase.common.doubleEncode(attr.name),
            leaf: !!attr.account_grants,
            allowDrop: !!attr.account_grants && attr.account_grants.addGrant
        });
        
        // copy 'real' data to container space
        attr.container = Ext.copyTo({}, attr, Tine.Tinebase.Model.Container.getFieldNames());
    },
    
    /**
     * returns params for async request
     * 
     * @param {Ext.tree.TreeNode} node
     * @return {Object}
     */
    onBeforeLoad: function(node) {
        var path = node.attributes.path;
        var type = Tine.Tinebase.container.path2type(path);
        var owner = Tine.Tinebase.container.pathIsPersonalNode(path);
        
        if (type === 'personal' && ! owner) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -495,12 +495,15 @@
         }
         
         Ext.applyIf(attr, {
-            text: Ext.util.Format.htmlEncode(attr.name),
-            qtip: Tine.Tinebase.common.doubleEncode(attr.name),
+            text: attr.name,
+            qtip: attr.name,
             leaf: !!attr.account_grants,
             allowDrop: !!attr.account_grants && attr.account_grants.addGrant
         });
-        
+
+        attr.text = Ext.util.Format.htmlEncode(attr.text);
+        attr.qtip = Ext.util.Format.htmlEncode(attr.qtip);
+
         // copy 'real' data to container space
         attr.container = Ext.copyTo({}, attr, Tine.Tinebase.Model.Container.getFieldNames());
     },
```
