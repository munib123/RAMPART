# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2824_9
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2824_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 65-105 of the vulnerable file.

            }]
        });
        
        this.on('click', this.onClick, this);
        this.on('beforeclick', this.onBeforeClick, this);
        this.on('contextmenu', this.onContextMenu, this);
        this.on('checkchange', this.onCheckChange, this);
        this.on('afterrender', this.onAfterRender, this);
        this.on('insert', this.onNodeInsert, this);
        this.on('textchange', this.onNodeTextChange, this);
        this.on('expandnode', this.filterPanel.manageHeight, this.filterPanel);
        this.on('collapsenode', this.filterPanel.manageHeight, this.filterPanel);
        this.on('collapse', this.filterPanel.manageHeight, this.filterPanel);
        this.on('expand', this.filterPanel.manageHeight, this.filterPanel);
        this.filterPanel.on('filterpaneladded', this.onFilterPanelAdded, this);
        this.filterPanel.on('filterpanelremoved', this.onFilterPanelRemoved, this);
        this.filterPanel.on('filterpanelactivate', this.onFilterPanelActivate, this);
        this.filterPanel.activeFilterPanel.on('titlechange', this.onFilterPanelTitleChange, this);
        
        this.editor = new Ext.tree.TreeEditor(this);
        
        Tine.widgets.grid.FilterStructureTreePanel.superclass.initComponent.call(this);
    },
    
    onContextMenu: function(node, e) {
        if (this.getRootNode().childNodes.length > 2 && node.id != 'addFilterPanel') {
            this.contextMenu.contextNode = node;
            this.contextMenu.showAt(e.getXY());
        }
    },
    
    onCtxRemove: function() {
        if (this.contextMenu.contextNode) {
            this.filterPanel.removeFilterPanel(this.contextMenu.contextNode.id);
        }
    },
    
    onAfterRender: function() {
        this.onFilterPanelActivate(this.filterPanel, this.filterPanel.activeFilterPanel);
//        this.getRootNode().collapse();
    },
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,6 +82,9 @@
         this.filterPanel.activeFilterPanel.on('titlechange', this.onFilterPanelTitleChange, this);
         
         this.editor = new Ext.tree.TreeEditor(this);
+        this.editor.on('startedit', function(el, value) {
+            this.editor.setValue(Ext.util.Format.htmlDecode(value));
+        }, this);
         
         Tine.widgets.grid.FilterStructureTreePanel.superclass.initComponent.call(this);
     },
@@ -113,7 +116,7 @@
      */
     onNodeTextChange: function(node, text, oldText) {
         if (node.attributes && node.attributes.filterPanel) {
-            node.attributes.filterPanel.setTitle(text);
+            node.attributes.filterPanel.setTitle(Ext.util.Format.htmlEncode(text));
         }
     },
     
```
