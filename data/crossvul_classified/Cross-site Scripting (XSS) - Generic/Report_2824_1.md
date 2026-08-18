# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2824_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2824_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 106-146 of the vulnerable file.

                text: 'default',
                draggable: false,
                allowDrop: false,
                expanded: true,
                leaf: false,
                id: 'root'
            });
        
            var mainApp = Ext.ux.PopupWindowMgr.getMainWindow().Tine.Tinebase.appMgr.get('Felamimail');
            mainApp.getAccountStore().each(function(record) {
                // TODO generalize this
                var node = new Ext.tree.AsyncTreeNode({
                    id: record.data.id,
                    path: '/' + record.data.id,
                    record: record,
                    globalname: '',
                    draggable: false,
                    allowDrop: false,
                    expanded: false,
                    text: Ext.util.Format.htmlEncode(record.get('name')),
                    qtip: Tine.Tinebase.common.doubleEncode(record.get('host')),
                    leaf: false,
                    cls: 'felamimail-node-account',
                    delimiter: record.get('delimiter'),
                    ns_personal: record.get('ns_personal'),
                    account_id: record.data.id
                });
            
                this.root.appendChild(node);
            }, this);
            
        } else {
            this.root = new Ext.tree.AsyncTreeNode({
                text: this.account.get('name'),
                draggable: false,
                allowDrop: false,
                expanded: true,
                leaf: false,
                cls: 'felamimail-node-account',
                id: this.account.id,
                path: '/' + this.account.id
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -123,7 +123,7 @@
                     allowDrop: false,
                     expanded: false,
                     text: Ext.util.Format.htmlEncode(record.get('name')),
-                    qtip: Tine.Tinebase.common.doubleEncode(record.get('host')),
+                    qtip: Ext.util.Format.htmlEncode(record.get('host')),
                     leaf: false,
                     cls: 'felamimail-node-account',
                     delimiter: record.get('delimiter'),
```
