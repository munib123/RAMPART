# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4190_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4190_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 155-194 of the vulnerable file.

};

function animateCSS(selector, animationName, callback, speed = "faster")
{
	var nodes = $(selector);
	nodes.addClass('animated').addClass(speed).addClass(animationName);

	function handleAnimationEnd()
	{
		nodes.removeClass('animated').removeClass(speed).removeClass(animationName);
		nodes.unbind('animationend', handleAnimationEnd);

		if (typeof callback === 'function')
		{
			callback();
		}
	}

	nodes.on('animationend', handleAnimationEnd);
}
function RandomString()
{
	return Math.random().toString(36).substring(2, 100) + Math.random().toString(36).substring(2, 100);
}
function getQRCodeForContent(url)
{
	var qr = qrcode(0, 'L');
	qr.addData(url);
	qr.make();
	return qr.createImgTag(10, 5);
}
function getQRCodeForAPIKey(apikey_type, apikey_key)
{
	var content = U('/api') + '|' + apikey_key;
	if (apikey_type === 'special-purpose-calendar-ical')
	{
		content = U('/api/calendar/ical?secret=' + apikey_key);
	}
	return getQRCodeForContent(content);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -172,10 +172,12 @@
 
 	nodes.on('animationend', handleAnimationEnd);
 }
+
 function RandomString()
 {
 	return Math.random().toString(36).substring(2, 100) + Math.random().toString(36).substring(2, 100);
 }
+
 function getQRCodeForContent(url)
 {
 	var qr = qrcode(0, 'L');
@@ -183,6 +185,7 @@
 	qr.make();
 	return qr.createImgTag(10, 5);
 }
+
 function getQRCodeForAPIKey(apikey_type, apikey_key)
 {
 	var content = U('/api') + '|' + apikey_key;
@@ -192,3 +195,8 @@
 	}
 	return getQRCodeForContent(content);
 }
+
+function SanitizeHtml(input)
+{
+	return $("<div/>").text(input).html();
+}
```
