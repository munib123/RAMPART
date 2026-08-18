# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 5208_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5208_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 10-50 of the vulnerable file.


function edit_interface(interface_id) {
  if (interface_id == null)
    form = get_interface_template_clone();
  else
    form = $('#interfaces #interfaceHidden'+interface_id).clone(true);
  show_interface_modal(form);
}

function show_interface_modal(modal_content) {
  var modal_window = $('#interfaceModal');
  var interface_id = modal_content.data('interface-id');

  modal_window.data('current-id', interface_id);

  var identifier = modal_content.find('.interface_identifier').val();


  modal_window.find('.modal-body').html('');
  modal_window.find('.modal-body').append(modal_content.contents());
  modal_window.find('.modal-title').html(__('Interface') + ' ' + String(identifier));
  modal_window.modal({'show': true});

  modal_window.find('a[rel="popover-modal"]').popover();
  activate_select2(modal_window);
}

function save_interface_modal() {
  var modal_window = $('#interfaceModal');
  var interface_id = modal_window.data('current-id');

  //destroy ui tools so when opening the modal again they will show correctly
  modal_window.find('a[rel="popover-modal"]').popover('destroy');
  modal_window.find('select').select2('destroy')

  // mark the selected values to preserve them for form hiding
  preserve_selected_options(modal_window);

  var modal_form = modal_window.find('.modal-body').contents();
  if (modal_form.find('.interface_primary').is(':checked')) {
    $('#interfaceForms .interface_primary:checked').attr("checked", false);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,7 @@
 
   modal_window.find('.modal-body').html('');
   modal_window.find('.modal-body').append(modal_content.contents());
-  modal_window.find('.modal-title').html(__('Interface') + ' ' + String(identifier));
+  modal_window.find('.modal-title').text(__('Interface') + ' ' + String(identifier));
   modal_window.modal({'show': true});
 
   modal_window.find('a[rel="popover-modal"]').popover();
@@ -158,10 +158,10 @@
   type += '</div>'
   row.find('.type').html(type);
 
-  row.find('.identifier').html(interface_form.find('.interface_identifier').val());
-  row.find('.mac').html(interface_form.find('.interface_mac').val());
-  row.find('.ip').html(interface_form.find('.interface_ip').val());
-  row.find('.ip6').html(interface_form.find('.interface_ip6').val());
+  row.find('.identifier').text(interface_form.find('.interface_identifier').val());
+  row.find('.mac').text(interface_form.find('.interface_mac').val());
+  row.find('.ip').text(interface_form.find('.interface_ip').val());
+  row.find('.ip6').text(interface_form.find('.interface_ip6').val());
 
   var flags = '', primary_class = '', provision_class = '';
   if (interface_form.find('.interface_primary').is(':checked'))
@@ -180,7 +180,7 @@
 
   row.find('.flags').html(flags);
 
-  row.find('.fqdn').html(fqdn(
+  row.find('.fqdn').text(fqdn(
     interface_form.find('.interface_name').val(),
     interface_form.find('.interface_domain option:selected').text()
   ));
```
