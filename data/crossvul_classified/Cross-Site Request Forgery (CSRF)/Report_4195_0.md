# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in javascript
**Pair ID:** 4195_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4195_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```javascript
Lines 69-109 of the vulnerable file.


	$('#update-show').click(function (e) {
		$('.nav-tabs a[href="/#update"]').tab('show');
	});

	$('.nav-tabs a').click(function(e) {
		$(this).tab('show');
	});

	$('.nav-tabs a[href="/' + window.location.hash + '"]').tab('show');

	$("#profile-mapper").submit(function(e) {
		e.preventDefault();

		var btn = $('#profile-mapper-save');
		btn.button('loading');

		$('#profile-mapper-alerts').html('');

		$.post('/profile-mapper', {
			code: code.getValue()
		}).always(function() {
			btn.button('reset');
		}).done(function() {
			$('#profile-mapper-alerts')
				.html('<div class="alert alert-success"><button type="button" class="close" data-dismiss="alert">&times;</button>The profile mapper script has been saved.</div>');
		}).fail(function(err) {
			$('#profile-mapper-alerts')
				.html('<div class="alert alert-error"><button type="button" class="close" data-dismiss="alert">&times;</button>Error saving the profile mapper script. Error: ' + err.statusText + '</div>');
		});
	});

	$("#scroll-top").click(function(e) {
		e.preventDefault();

		scrollToTop();
	});

	function scrollToTop() {
		setTimeout(function() {
			window.scrollTo(0, 0);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -86,6 +86,7 @@
 		$('#profile-mapper-alerts').html('');
 
 		$.post('/profile-mapper', {
+			_csrf: document.getElementById('csrf').value,
 			code: code.getValue()
 		}).always(function() {
 			btn.button('reset');
@@ -131,7 +132,9 @@
 	$("#logs-clear").click(function(e) {
 		e.preventDefault();
 
-		$.post('/logs/clear');
+		$.post('/logs/clear', {
+			_csrf: document.getElementById('csrf').value
+		});
 		$('#logs').text('');
 	});
 
@@ -238,7 +241,9 @@
 	$("#update-run-form").submit(function(e) {
 		e.preventDefault();
 
-		$.post('/updater/run');
+		$.post('/updater/run', {
+			_csrf: document.getElementById('csrf').value,
+		});
 
 		update = 'Started';
 		$('#update-logs').text('');
```
