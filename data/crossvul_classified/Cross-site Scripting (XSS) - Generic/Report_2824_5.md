# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2824_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2824_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 175-215 of the vulnerable file.

        if(contenttype) {
            var iconClass = contenttype.replace("/", "-");
            metadata.css = iconClass + '_16x16 ';
        }
               
        metadata.css += 'standardFileClass_16x16';
    }
    
    
    if (!Tine.Tinebase.uploadManager.isHtml5ChunkedUpload()) {

        var fileName = value;
        if (typeof value == 'object') {
            fileName = value.name;
        } 
    
        if(record.get('status') == 'uploading') {
            metadata.css = 'x-tinebase-uploadrow';
        }
        
        return fileName;
    }
    
    if (! Ext.ux.PercentRendererWithName.template) {
        Ext.ux.PercentRendererWithName.template = new Ext.XTemplate(
            '<div class="x-progress-wrap PercentRenderer" style="{display}">',
            '<div class="x-progress-inner PercentRenderer">',
                '<div class="x-progress-bar PercentRenderer" style="width:{percent}%;{additionalStyle}">',
                    '<div class="PercentRendererText PercentRenderer">',
                         '{fileName}',
                    '</div>',
                '</div>',
                '<div class="x-progress-text x-progress-text-back PercentRenderer">',
                    '<div>&#160;</div>',
                '</div>',
            '</div>',
        '</div>'
        ).compile();
    }
    
    if(value == undefined) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -192,7 +192,7 @@
             metadata.css = 'x-tinebase-uploadrow';
         }
         
-        return fileName;
+        return Ext.util.Format.htmlEncode(fileName);
     }
     
     if (! Ext.ux.PercentRendererWithName.template) {
@@ -221,7 +221,7 @@
     if (typeof value == 'object') {
         fileName = value.name;
     }
-    
+    fileName = Ext.util.Format.htmlEncode(fileName);
     var percent = record.get('progress');
 
     var additionalStyle = '';
@@ -229,7 +229,7 @@
         fileName = _('(paused)') + '&#160;&#160;' + fileName;
         additionalStyle = 'background-image: url(\'styles/images/tine20/progress/progress-bg-y.gif\') !important;';
     }
-       
+
     var display = 'width:0px';
     if(percent > -1 && percent < 100) {
         display = '';
```
