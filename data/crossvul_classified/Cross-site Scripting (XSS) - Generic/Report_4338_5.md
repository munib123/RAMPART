# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4338_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4338_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 39-81 of the vulnerable file.

    $('.grade-stars').rating();
  });

  const updateCommentPostErrorModal = $('#update-comment-usefulness-post-error');

  const confirmAbuseModal = $('#report-comment-confirmation');
  const reportCommentPostErrorModal = $('#report-comment-post-error');
  const reportCommentPostedModal = $('#report-comment-posted');

  function showUpdatePostCommentErrorModal(errorMessage) {
    $('#update-comment-usefulness-post-error-message').html(errorMessage);
    updateCommentPostErrorModal.modal('show');
  }

  function showReportCommentErrorModal(errorMessage) {
    $('#report-comment-post-error-message').html(errorMessage);
    reportCommentPostErrorModal.modal('show');
  }

  function paginateComments(page) {
    $.get(commentsListUrl, {page: page}, function(result) {
      const jsonResponse = JSON.parse(result);

      if (jsonResponse.comments && jsonResponse.comments.length > 0) {
        populateComments(jsonResponse.comments);
        if (jsonResponse.comments_nb > jsonResponse.comments_per_page) {
          $('#product-comments-list-pagination').pagination({
            currentPage: page,
            items: jsonResponse.comments_nb,
            itemsOnPage: jsonResponse.comments_per_page,
            cssStyle: '',
            prevText: '<i class="material-icons">chevron_left</i>',
            nextText: '<i class="material-icons">chevron_right</i>',
            useAnchors: false,
            displayedPages: 2,
            onPageClick: paginateComments
          });
        } else {
          $('#product-comments-list-pagination').hide();
        }
      } else {
        commentsList.html('');
        emptyProductComment.show();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,9 +56,7 @@
   }
 
   function paginateComments(page) {
-    $.get(commentsListUrl, {page: page}, function(result) {
-      const jsonResponse = JSON.parse(result);
-
+    $.get(commentsListUrl, {page: page}, function(jsonResponse) {
       if (jsonResponse.comments && jsonResponse.comments.length > 0) {
         populateComments(jsonResponse.comments);
         if (jsonResponse.comments_nb > jsonResponse.comments_per_page) {
@@ -123,12 +121,7 @@
   }
 
   function updateCommentUsefulness($comment, commentId, usefulness) {
-    $.post(updateCommentUsefulnessUrl, {id_product_comment: commentId, usefulness: usefulness}, function(jsonResponse){
-      var jsonData = false;
-      try {
-        jsonData = JSON.parse(jsonResponse);
-      } catch (e) {
-      }
+    $.post(updateCommentUsefulnessUrl, {id_product_comment: commentId, usefulness: usefulness}, function(jsonData){
       if (jsonData) {
         if (jsonData.success) {
           $('.useful-review-value', $comment).html(jsonData.usefulness);
@@ -151,12 +144,7 @@
       if (!confirm) {
         return;
       }
-      $.post(reportCommentUrl, {id_product_comment: commentId}, function(jsonResponse){
-        var jsonData = false;
-        try {
-          jsonData = JSON.parse(jsonResponse);
-        } catch (e) {
-        }
+      $.post(reportCommentUrl, {id_product_comment: commentId}, function(jsonData){
         if (jsonData) {
           if (jsonData.success) {
             reportCommentPostedModal.modal('show');
```
