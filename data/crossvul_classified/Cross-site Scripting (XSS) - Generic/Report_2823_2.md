# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2823_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2823_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 108-154 of the vulnerable file.

                    }
                },
                scope: this,
                prompt: true,
                icon: Ext.MessageBox.QUESTION
            });
        }
    },
    
    /**
     * delete tree node
     */
    deleteNode: function() {
        if (this.scope.ctxNode) {
            var nodes = this.scope.ctxNode;
            
            var nodeName = "";
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
                title: this.scope.app.i18n._('Do you really want to delete the following files?'),
                text: nodeName,
                scope: this,
                handler: function(button){
                    if (button == 'yes') {
                        var params = {
                                method: this.backend + '.delete' + this.backendModel
                        };
                        
                        if (this.backendModel == 'Node') {
                            
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -125,15 +125,11 @@
             if(nodes && nodes.length) {
                 for(var i=0; i<nodes.length; i++) {
                     var currNodeData = nodes[i].data;
-                    
-                    if(typeof currNodeData.name == 'object') {
-                        nodeName += currNodeData.name.name + '<br />';
-                    }
-                    else {
-                        nodeName += currNodeData.name + '<br />';
-                    }
+
+                    nodeName += Ext.util.Format.htmlEncode(typeof currNodeData.name == 'object' ?
+                        currNodeData.name.name :
+                        currNodeData.name) + '<br />';
                 }
-                
             }
             
             this.conflictConfirmWin = Tine.widgets.dialog.FileListDialog.openWindow({
```
