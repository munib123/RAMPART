# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3796_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3796_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-38 of the vulnerable file.

var FileList={
	useUndo:true,
	update:function(fileListHtml) {
		$('#fileList').empty().html(fileListHtml);
	},
	addFile:function(name,size,lastModified,loading,hidden){
		var basename, extension, simpleSize, sizeColor, lastModifiedTime, modifiedColor,
			img=(loading)?OC.imagePath('core', 'loading.gif'):OC.imagePath('core', 'filetypes/file.png'),
			html='<tr data-type="file" data-size="'+size+'" data-permissions="'+$('#permissions').val()+'">';
		if(name.indexOf('.')!=-1){
			basename=name.substr(0,name.lastIndexOf('.'));
			extension=name.substr(name.lastIndexOf('.'));
		}else{
			basename=name;
			extension=false;
		}
		html+='<td class="filename" style="background-image:url('+img+')"><input type="checkbox" />';
		html+='<a class="name" href="download.php?file='+$('#dir').val().replace(/</, '&lt;').replace(/>/, '&gt;')+'/'+name+'"><span class="nametext">'+basename;
		if(extension){
			html+='<span class="extension">'+extension+'</span>';
		}
		html+='</span></a></td>';
		if(size!='Pending'){
			simpleSize=simpleFileSize(size);
		}else{
			simpleSize='Pending';
		}
		sizeColor = Math.round(200-size/(1024*1024)*2);
		lastModifiedTime=Math.round(lastModified.getTime() / 1000);
		modifiedColor=Math.round((Math.round((new Date()).getTime() / 1000)-lastModifiedTime)/60/60/24*14);
		html+='<td class="filesize" title="'+humanFileSize(size)+'" style="color:rgb('+sizeColor+','+sizeColor+','+sizeColor+')">'+simpleSize+'</td>';
		html+='<td class="date"><span class="modified" title="'+formatDate(lastModified)+'" style="color:rgb('+modifiedColor+','+modifiedColor+','+modifiedColor+')">'+relative_modified_date(lastModified.getTime() / 1000)+'</span></td>';
		html+='</tr>';
		FileList.insertElement(name,'file',$(html).attr('data-file',name));
		if(loading){
			$('tr').filterAttr('data-file',name).data('loading',true);
		}else{
			$('tr').filterAttr('data-file',name).find('td.filename').draggable(dragOptions);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,9 +15,9 @@
 			extension=false;
 		}
 		html+='<td class="filename" style="background-image:url('+img+')"><input type="checkbox" />';
-		html+='<a class="name" href="download.php?file='+$('#dir').val().replace(/</, '&lt;').replace(/>/, '&gt;')+'/'+name+'"><span class="nametext">'+basename;
+		html+='<a class="name" href="download.php?file='+$('#dir').val().replace(/</, '&lt;').replace(/>/, '&gt;')+'/'+escapeHTML(name)+'"><span class="nametext">'+escapeHTML(basename);
 		if(extension){
-			html+='<span class="extension">'+extension+'</span>';
+			html+='<span class="extension">'+escapeHTML(extension)+'</span>';
 		}
 		html+='</span></a></td>';
 		if(size!='Pending'){
@@ -189,9 +189,9 @@
 	checkName:function(oldName, newName, isNewFile) {
 		if (isNewFile || $('tr').filterAttr('data-file', newName).length > 0) {
 			if (isNewFile) {
-				$('#notification').html(newName+' '+t('files', 'already exists')+'<span class="replace">'+t('files', 'replace')+'</span><span class="suggest">'+t('files', 'suggest name')+'</span><span class="cancel">'+t('files', 'cancel')+'</span>');
+				$('#notification').html(escapeHTML(newName)+' '+t('files', 'already exists')+'<span class="replace">'+t('files', 'replace')+'</span><span class="suggest">'+t('files', 'suggest name')+'</span><span class="cancel">'+t('files', 'cancel')+'</span>');
 			} else {
-				$('#notification').html(newName+' '+t('files', 'already exists')+'<span class="replace">'+t('files', 'replace')+'</span><span class="cancel">'+t('files', 'cancel')+'</span>');
+				$('#notification').html(escapeHTML(newName)+' '+t('files', 'already exists')+'<span class="replace">'+t('files', 'replace')+'</span><span class="cancel">'+t('files', 'cancel')+'</span>');
 			}
 			$('#notification').data('oldName', oldName);
 			$('#notification').data('newName', newName);
@@ -272,9 +272,9 @@
 		} else {
 			// NOTE: Temporary fix to change the text to unshared for files in root of Shared folder
 			if ($('#dir').val() == '/Shared') {
-				$('#notification').html(t('files', 'unshared')+' '+files+'<span class="undo">'+t('files', 'undo')+'</span>');
+				$('#notification').html(t('files', 'unshared')+' '+ escapeHTML(files) +'<span class="undo">'+t('files', 'undo')+'</span>');
 			} else {
-				$('#notification').html(t('files', 'deleted')+' '+files+'<span class="undo">'+t('files', 'undo')+'</span>');
+				$('#notification').html(t('files', 'deleted')+' '+ escapeHTML(files)+'<span class="undo">'+t('files', 'undo')+'</span>');
 			}
 			$('#notification').fadeIn();
 		}
```
