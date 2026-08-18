# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 703_10
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `703_10`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 715-755 of the vulnerable file.

		hideSpinner();
    }).fail(function(jqxhr, textStatus, errorThrown) { showError(jqxhr.statusText + "<br>Status: " + textStatus + "<br>Error: "+errorThrown); });	return false;
});
//show telnet port
$(document).on('change', "table.table-scan select#type", function() {
	var pingType = $('select[name=type]').find(":selected").val();
	if(pingType=="scan-telnet") { $('tbody#telnetPorts').show(); }
	else 						{ $('tbody#telnetPorts').hide(); }
});
//save value to cookie
$(document).on('change', "table.table-scan select#type", function() {
    var sel = ($(this).find(":selected").val());
    createCookie("scantype",sel,32);
});

//start scanning
$(document).on('click','#subnetScanSubmit', function() {
	showSpinner();
	$('#subnetScanResult').slideUp('fast');
	var subnetId = $(this).attr('data-subnetId');
	var type 	 = $('select[name=type]').find(":selected").val();
	if($('input[name=debug]').is(':checked'))	{ var debug = 1; }
	else										{ var debug = 0; }
	var port     = $('input[name=telnetports]').val();
	$('#alert-scan').slideUp('fast');
	$.post('app/subnets/scan/subnet-scan-execute.php', {subnetId:subnetId, type:type, debug:debug, port:port}, function(data) {
        $('#subnetScanResult').html(data).slideDown('fast');
		hideSpinner();
    }).fail(function(jqxhr, textStatus, errorThrown) { showError(jqxhr.statusText + "<br>Status: " + textStatus + "<br>Error: "+errorThrown); });	return false;
});
//remove result
$(document).on('click', '.resultRemove', function() {
	// if MAC table show IP that is hidden
	if ($(this).hasClass('resultRemoveMac')) {
    	// if this one is hidden dont show ip for next
    	if ($(this).parent().parent().find('span.ip-address').hasClass('hidden')) {

    	}
    	// else show
        else {
            $(this).parent().parent().next().find('span.ip-address').removeClass('hidden');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -732,12 +732,13 @@
 	showSpinner();
 	$('#subnetScanResult').slideUp('fast');
 	var subnetId = $(this).attr('data-subnetId');
+	var csrf     = $(this).attr('data-csrf-cookie');
 	var type 	 = $('select[name=type]').find(":selected").val();
 	if($('input[name=debug]').is(':checked'))	{ var debug = 1; }
 	else										{ var debug = 0; }
 	var port     = $('input[name=telnetports]').val();
 	$('#alert-scan').slideUp('fast');
-	$.post('app/subnets/scan/subnet-scan-execute.php', {subnetId:subnetId, type:type, debug:debug, port:port}, function(data) {
+	$.post('app/subnets/scan/subnet-scan-execute.php', {subnetId:subnetId, type:type, debug:debug, port:port, csrf_cookie:csrf}, function(data) {
         $('#subnetScanResult').html(data).slideDown('fast');
 		hideSpinner();
     }).fail(function(jqxhr, textStatus, errorThrown) { showError(jqxhr.statusText + "<br>Status: " + textStatus + "<br>Error: "+errorThrown); });	return false;
```
