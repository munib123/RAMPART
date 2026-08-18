# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4513_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4513_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 177-217 of the vulnerable file.

froalaOptions.htmlAllowedTags=this.options.allowTags?this.options.allowTags.split(/[\s,]+/):['a','abbr','address','area','article','aside','audio','b','bdi','bdo','blockquote','br','button','canvas','caption','cite','code','col','colgroup','datalist','dd','del','details','dfn','dialog','div','dl','dt','em','embed','fieldset','figcaption','figure','footer','form','h1','h2','h3','h4','h5','h6','header','hgroup','hr','i','iframe','img','input','ins','kbd','keygen','label','legend','li','link','main','map','mark','menu','menuitem','meter','nav','noscript','object','ol','optgroup','option','output','p','param','pre','progress','queue','rp','rt','ruby','s','samp','script','style','section','select','small','source','span','strike','strong','sub','summary','sup','table','tbody','td','textarea','tfoot','th','thead','time','title','tr','track','u','ul','var','video','wbr']
froalaOptions.htmlDoNotWrapTags=this.options.noWrapTags?this.options.noWrapTags.split(/[\s,]+/):['figure','script','style']
froalaOptions.htmlRemoveTags=this.options.removeTags?this.options.removeTags.split(/[\s,]+/):['script','style','base']
froalaOptions.lineBreakerTags=this.options.lineBreakerTags?this.options.lineBreakerTags.split(/[\s,]+/):['figure, table, hr, iframe, form, dl']
froalaOptions.shortcutsEnabled=['show','bold','italic','underline','indent','outdent','undo','redo']
froalaOptions.requestHeaders={'X-CSRF-TOKEN':$('meta[name="csrf-token"]').attr('content'),'X-Requested-With':'XMLHttpRequest'}
var $form=this.$el.closest('form')
var formData={};if($form.length>0){$.each($form.serializeArray(),function(index,field){formData[field.name]=field.value;})}
froalaOptions.imageUploadURL=froalaOptions.fileUploadURL=window.location
froalaOptions.imageUploadParam=froalaOptions.fileUploadParam='file_data'
froalaOptions.imageUploadParams=froalaOptions.fileUploadParams=$.extend(formData,{_handler:froalaOptions.uploadHandler,})
var placeholder=this.$textarea.attr('placeholder')
froalaOptions.placeholderText=placeholder?placeholder:''
froalaOptions.height=this.$el.hasClass('stretch')?Infinity:$('.height-indicator',this.$el).height()
if(!this.options.useMediaManager){delete $.FroalaEditor.PLUGINS.mediaManager}
$.FroalaEditor.ICON_TEMPLATES={font_awesome:'<i class="icon-[NAME]"></i>',text:'<span style="text-align: center;">[NAME]</span>',image:'<img src=[SRC] alt=[ALT] />'}
this.$textarea.on('froalaEditor.initialized',this.proxy(this.build))
this.$textarea.on('froalaEditor.contentChanged',this.proxy(this.onChange))
this.$textarea.on('froalaEditor.html.get',this.proxy(this.onSyncContent))
this.$textarea.on('froalaEditor.html.set',this.proxy(this.onSetContent))
this.$form.on('oc.beforeRequest',this.proxy(this.onFormBeforeRequest))
this.$textarea.froalaEditor(froalaOptions)
this.editor=this.$textarea.data('froala.editor')
if(this.options.readOnly){this.editor.edit.off()}
this.$el.on('keydown','.fr-view figure',this.proxy(this.onFigureKeydown))}
RichEditor.prototype.dispose=function(){this.unregisterHandlers()
this.$textarea.froalaEditor('destroy')
this.$el.removeData('oc.richEditor')
this.options=null
this.$el=null
this.$textarea=null
this.$form=null
this.editor=null
BaseProto.dispose.call(this)}
RichEditor.prototype.unregisterHandlers=function(){this.$el.off('keydown','.fr-view figure',this.proxy(this.onFigureKeydown))
this.$textarea.off('froalaEditor.initialized',this.proxy(this.build))
this.$textarea.off('froalaEditor.contentChanged',this.proxy(this.onChange))
this.$textarea.off('froalaEditor.html.get',this.proxy(this.onSyncContent))
this.$textarea.off('froalaEditor.html.set',this.proxy(this.onSetContent))
this.$form.off('oc.beforeRequest',this.proxy(this.onFormBeforeRequest))
$(window).off('resize',this.proxy(this.updateLayout))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -194,6 +194,7 @@
 this.$textarea.on('froalaEditor.contentChanged',this.proxy(this.onChange))
 this.$textarea.on('froalaEditor.html.get',this.proxy(this.onSyncContent))
 this.$textarea.on('froalaEditor.html.set',this.proxy(this.onSetContent))
+this.$textarea.on('froalaEditor.paste.beforeCleanup',this.proxy(this.beforeCleanupPaste))
 this.$form.on('oc.beforeRequest',this.proxy(this.onFormBeforeRequest))
 this.$textarea.froalaEditor(froalaOptions)
 this.editor=this.$textarea.data('froala.editor')
@@ -213,6 +214,7 @@
 this.$textarea.off('froalaEditor.contentChanged',this.proxy(this.onChange))
 this.$textarea.off('froalaEditor.html.get',this.proxy(this.onSyncContent))
 this.$textarea.off('froalaEditor.html.set',this.proxy(this.onSetContent))
+this.$textarea.off('froalaEditor.paste.beforeCleanup',this.proxy(this.beforeCleanupPaste))
 this.$form.off('oc.beforeRequest',this.proxy(this.onFormBeforeRequest))
 $(window).off('resize',this.proxy(this.updateLayout))
 $(window).off('oc.updateUi',this.proxy(this.updateLayout))
@@ -243,6 +245,7 @@
 RichEditor.prototype.insertVideo=function(url,title){this.$textarea.froalaEditor('figures.insertVideo',url,title)}
 RichEditor.prototype.insertAudio=function(url,title){this.$textarea.froalaEditor('figures.insertAudio',url,title)}
 RichEditor.prototype.onSetContent=function(ev,editor){this.$textarea.trigger('setContent.oc.richeditor',[this])}
+RichEditor.prototype.beforeCleanupPaste=function(ev,editor,clipboard_html){return ocSanitize(clipboard_html)}
 RichEditor.prototype.onSyncContent=function(ev,editor,html){if(editor.codeBeautifier){html=editor.codeBeautifier.run(html,editor.opts.codeBeautifierOptions)}
 var container={html:html}
 this.$textarea.trigger('syncContent.oc.richeditor',[this,container])
```
