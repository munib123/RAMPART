# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2824_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2824_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 764-804 of the vulnerable file.

            folder.commit();
        }
    },
    
    /**
     * add account record to root node
     * 
     * @param {Tine.Felamimail.Model.Account} record
     */
    addAccount: function(record) {
        
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
            account_id: record.data.id,
            listeners: {
                scope: this,
                load: function(node) {
                    var account = this.accountStore.getById(node.id);
                    this.updateAccountStatus(account);
                }
            }
        });
        
        // we don't want appending folder effects
        this.suspendEvents();
        this.root.appendChild(node);
        this.resumeEvents();
    },
    
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -781,7 +781,7 @@
             allowDrop: false,
             expanded: false,
             text: Ext.util.Format.htmlEncode(record.get('name')),
-            qtip: Tine.Tinebase.common.doubleEncode(record.get('host')),
+            qtip: Ext.util.Format.htmlEncode(record.get('host')),
             leaf: false,
             cls: 'felamimail-node-account',
             delimiter: record.get('delimiter'),
```
