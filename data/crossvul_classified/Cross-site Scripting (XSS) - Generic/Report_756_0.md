# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 756_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `756_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 173-213 of the vulnerable file.

				common.notifications.messages.push(message);
				!common.notifications.running && refresh_notifications();
			}
		});

		ON('online', function(is) {
			$('.user .fa').tclass('green', is).tclass('red', !is);
		});

		function refresh_notifications() {
			var item = common.notifications.messages.shift();

			if (item === undefined) {
				common.notifications.ui.el.rclass('header-message-visible');
				common.notifications.running = false;
				return;
			}

			var msg = '';
			var t = common.notifications.template;
			switch (item.type) {

				case 'navigation.save':
					msg = t.format('@(Navigation has been saved)', item.message);
					break;

				case 'navigations/edit':
				case 'pages/edit':
				case 'posts/edit':
				case 'newsletters/edit':
				case 'notices/edit':
				case 'widgets/edit':

					if (user.name !== item.user) {
						var tmp = item.type.substring(0, item.type.indexOf('/'));
						if (tmp === 'navigations')
							tmp = 'pages-navigation';
						else
							tmp += '-form';
						if (tmp === common.form)
							SETTER('snackbar', 'warning', '@(<b>IMPORTANT:</b> The user called "<b>{0}</b>" is editing same item.)'.format(user.name));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -190,6 +190,10 @@
 
 			var msg = '';
 			var t = common.notifications.template;
+
+			if (item.message)
+				item.message = Thelpers.encode(item.message);
+
 			switch (item.type) {
 
 				case 'navigation.save':
```
