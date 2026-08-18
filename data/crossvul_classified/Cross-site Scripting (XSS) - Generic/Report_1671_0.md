# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1671_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1671_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-28 of the vulnerable file.

function turn_textarea_switch(checkbox) {
  var target, session;
  var id = checkbox.id.replace(/hidden_value$/, "value");
  var source = document.getElementById(id);
  var $editorContainer = $('.editor-container');

  if (checkbox.checked) {
    target = '<input class="form-control" type="password" id="' + id + '" name="' + source.name + '" value ="' + source.value + '"></input>'
    $editorContainer.find('.navbar').hide();
    $editorContainer.find('.ace_editor').remove();
    $(source).replaceWith(target);
  } else if ($('.editor-container').length > 0) {
    target = '<textarea class="form-control editor_source hide" id="' + id + '" name="' + source.name + '" placeholder="Value" rows="1">' + source.value + '</textarea>'
    $editorContainer.find('.navbar').show();
    $(source).replaceWith(target);

    onEditorLoad();
    session = Editor.getSession();
    session.setValue($(source).val());
  } else {
    var target = '<textarea class="form-control" id="' + id + '" name="' + source.name + '" placeholder="Value" rows="1">' + source.value + '</textarea>'
    $(source).replaceWith(target);
  }
}
function hidden_value_control(){
  $(".toggle-hidden-value a").click(function(event){
    event.preventDefault();
    var link = $(event.currentTarget);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,12 +5,12 @@
   var $editorContainer = $('.editor-container');
 
   if (checkbox.checked) {
-    target = '<input class="form-control" type="password" id="' + id + '" name="' + source.name + '" value ="' + source.value + '"></input>'
+    target = $('<input/>').attr({ type: 'password', id: id, name: source.name, value: $(source).val(), class: 'form-control'});
     $editorContainer.find('.navbar').hide();
     $editorContainer.find('.ace_editor').remove();
     $(source).replaceWith(target);
   } else if ($('.editor-container').length > 0) {
-    target = '<textarea class="form-control editor_source hide" id="' + id + '" name="' + source.name + '" placeholder="Value" rows="1">' + source.value + '</textarea>'
+    target = $('<textarea/>').attr({class: 'form-control editor_source hide', id: id, name: source.name, placeholder: 'Value', rows: 1, value: $(source).val()});
     $editorContainer.find('.navbar').show();
     $(source).replaceWith(target);
 
@@ -18,7 +18,7 @@
     session = Editor.getSession();
     session.setValue($(source).val());
   } else {
-    var target = '<textarea class="form-control" id="' + id + '" name="' + source.name + '" placeholder="Value" rows="1">' + source.value + '</textarea>'
+    var target = $('<textarea/>').attr({class: 'form-control', id: id, name: source.name, placeholder: 'Value', rows: 1, value: $(source).val()});
     $(source).replaceWith(target);
   }
 }
```
