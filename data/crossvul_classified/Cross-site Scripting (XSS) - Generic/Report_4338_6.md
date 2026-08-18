# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4338_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4338_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 67-112 of the vulnerable file.

    $('#post-product-comment-form textarea').removeClass('valid error');
    $('#post-product-comment-form .criterion-rating input').val(3).change();
  }

  function initCommentModal() {
    $('#post-product-comment-modal .grade-stars').rating();
    $('body').on('click', '.post-product-comment', function (event) {
      event.preventDefault();
      showPostCommentModal();
    });

    $('#post-product-comment-form').submit(submitCommentForm);
  }

  function submitCommentForm(event) {
    event.preventDefault();
    var formData = $(this).serializeArray();
    if (!validateFormData(formData)) {
      return;
    }
    $.post($(this).attr('action'), $(this).serialize(), function(jsonResponse) {
      var jsonData = false;
      try {
        jsonData = JSON.parse(jsonResponse);
      } catch (e) {
      }
      if (jsonData) {
        if (jsonData.success) {
          clearPostCommentForm();
          showCommentPostedModal();
        } else {
          if (jsonData.errors) {
            var errorList = '<ul>';
            for (var i = 0; i < jsonData.errors.length; ++i) {
              errorList += '<li>' + jsonData.errors[i] + '</li>';
            }
            errorList += '</ul>';
            showPostErrorModal(errorList);
          } else {
            const decodedErrorMessage = $("<div/>").html(jsonData.error).text();
            showPostErrorModal(decodedErrorMessage);
          }
        }
      } else {
        showPostErrorModal(productCommentPostErrorMessage);
      }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,12 +84,7 @@
     if (!validateFormData(formData)) {
       return;
     }
-    $.post($(this).attr('action'), $(this).serialize(), function(jsonResponse) {
-      var jsonData = false;
-      try {
-        jsonData = JSON.parse(jsonResponse);
-      } catch (e) {
-      }
+    $.post($(this).attr('action'), $(this).serialize(), function(jsonData) {
       if (jsonData) {
         if (jsonData.success) {
           clearPostCommentForm();
```
