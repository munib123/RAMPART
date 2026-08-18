# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3750_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3750_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 3-43 of the vulnerable file.


var bookmarks_sorting = 'bookmarks_sorting_recent';

$(document).ready(function() {
	$('#bookmark_add_submit').click(addOrEditBookmark);
	$(window).resize(function () {
		fillWindow($('.bookmarks_list'));
	});
	$(window).resize();
	$('.bookmarks_list').scroll(updateOnBottom).empty().width($('#content').width());
	getBookmarks();
});

function getBookmarks() {
	if(bookmarks_loading) {
		//have patience :)
		return;
	}

	$.ajax({
		url: OC.filePath('bookmarks', 'ajax', 'updateList.php'),
		data: 'tag=' + encodeURIComponent($('#bookmarkFilterTag').val()) + '&page=' + bookmarks_page + '&sort=' + bookmarks_sorting,
		success: function(bookmarks){
			if (bookmarks.data.length) {
				bookmarks_page += 1;
			}
			$('.bookmark_link').unbind('click', recordClick);
			$('.bookmark_delete').unbind('click', delBookmark);
			$('.bookmark_edit').unbind('click', showBookmark);

			for(var i in bookmarks.data) {
				updateBookmarksList(bookmarks.data[i]);
				$("#firstrun").hide();
			}
			if($('.bookmarks_list').is(':empty')) {
				$("#firstrun").show();
			}

			$('.bookmark_link').click(recordClick);
			$('.bookmark_delete').click(delBookmark);
			$('.bookmark_edit').click(showBookmark);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,6 +20,7 @@
 	}
 
 	$.ajax({
+		  type: 'POST',
 		url: OC.filePath('bookmarks', 'ajax', 'updateList.php'),
 		data: 'tag=' + encodeURIComponent($('#bookmarkFilterTag').val()) + '&page=' + bookmarks_page + '&sort=' + bookmarks_sorting,
 		success: function(bookmarks){
@@ -70,6 +71,7 @@
 	}
 	if (id == 0) {
 		$.ajax({
+			type: 'POST',
 			url: OC.filePath('bookmarks', 'ajax', 'addBookmark.php'),
 			data: 'url=' + encodeURIComponent(url) + '&title=' + encodeURIComponent(title) + '&tags=' + encodeURIComponent(tags),
 			success: function(response){
@@ -82,6 +84,7 @@
 	}
 	else {
 		$.ajax({
+			type: 'POST',
 			url: OC.filePath('bookmarks', 'ajax', 'editBookmark.php'),
 			data: 'id=' + id + '&url=' + encodeURIComponent(url) + '&title=' + encodeURIComponent(title) + '&tags=' + encodeURIComponent(tags),
 			success: function(){
@@ -99,6 +102,7 @@
 function delBookmark(event) {
 	var record = $(this).parent().parent();
 	$.ajax({
+		type: 'POST',
 		url: OC.filePath('bookmarks', 'ajax', 'delBookmark.php'),
 		data: 'id=' + record.data('id'),
 		success: function(data){
@@ -177,6 +181,7 @@
 
 function recordClick(event) {
 	$.ajax({
+		type: 'POST',
 		url: OC.filePath('bookmarks', 'ajax', 'recordClick.php'),
 		data: 'url=' + encodeURIComponent($(this).attr('href')),
 	});
```
