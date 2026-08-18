# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in css
**Pair ID:** 5234_3
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** css
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5234_3`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```css
Lines 1380-1420 of the vulnerable file.

	background-color: #fff8e5;
}

.notice-error,
div.error {
	border-left-color: #dc3232;
}

.notice-error.notice-alt {
	background-color: #fbeaea;
}

.notice-info {
	border-left-color: #00a0d2;
}

.notice-info.notice-alt {
	background-color: #e5f5fa;
}

.wrap .notice,
.wrap div.updated,
.wrap div.error,
.media-upload-form .notice,
.media-upload-form div.error {
	margin: 5px 0 15px;
}

#update-nag,
.update-nag {
	display: inline-block;
	line-height: 19px;
	padding: 11px 15px;
	font-size: 14px;
	text-align: left;
	margin: 25px 20px 0 2px;
	background-color: #fff;
	border-left: 4px solid #ffba00;
	-webkit-box-shadow: 0 1px 1px 0 rgba(0,0,0,0.1);
	box-shadow: 0 1px 1px 0 rgba(0,0,0,0.1);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1397,12 +1397,66 @@
 	background-color: #e5f5fa;
 }
 
+.update-message p:before,
+.updating-message p:before,
+.updated-message p:before,
+.import-php .updating-message:before,
+.button.updating-message:before,
+.button.updated-message:before,
+.button.installed:before,
+.button.installing:before {
+	display: inline-block;
+	font: normal 20px/1 'dashicons';
+	-webkit-font-smoothing: antialiased;
+	-moz-osx-font-smoothing: grayscale;
+	vertical-align: top;
+}
+
 .wrap .notice,
 .wrap div.updated,
 .wrap div.error,
 .media-upload-form .notice,
 .media-upload-form div.error {
 	margin: 5px 0 15px;
+}
+
+/* Update icon. */
+.update-message p:before,
+.updating-message p:before,
+.import-php .updating-message:before,
+.button.updating-message:before,
+.button.installing:before {
+	color: #f56e28;
+	content: "\f463";
+}
+
+/* Spins the update icon. */
+.updating-message p:before,
+.import-php .updating-message:before,
+.button.updating-message:before,
+.button.installing:before {
+	-webkit-animation: rotation 2s infinite linear;
+	animation: rotation 2s infinite linear;
+}
+
+/* Updated icon (check mark). */
+.updated-message p:before,
+.installed p:before,
+.button.updated-message:before {
+	color: #79ba49;
+	content: '\f147';
+}
+
+/* Error icon. */
+.update-message.notice-error p:before {
+	 color: #dc3232;
+	 content: "\f534";
+}
+
+.wrap .notice p:before,
+.import-php .updating-message:before {
+	margin-right: 6px;
+	vertical-align: bottom;
 }
 
 #update-nag,
@@ -1419,10 +1473,6 @@
 	box-shadow: 0 1px 1px 0 rgba(0,0,0,0.1);
 }
 
-.update-message {
-	color: #000;
-}
-
 ul#dismissed-updates {
 	display: none;
 }
@@ -1453,6 +1503,50 @@
 #ajax-response.alignleft {
 	margin-left: 2em;
 }
+
+.button.updating-message:before,
+.button.updated-message:before,
+.button.installed:before,
+.button.installing:before {
+	margin: 3px 5px 0 -2px;
+}
+
+.button-primary.updating-message:before {
+	color: #fff;
+}
+
+.button-primary.updated-message:before {
+	color: #66c6e4;
+}
+
+.button.updated-message,
+.notice .button-link {
+	-webkit-transition-property: border, background, color;
+	transition-property: border, background, color;
+	-webkit-transition-duration: .05s;
+	transition-duration: .05s;
+	-webkit-transition-timing-function: ease-in-out;
+	transition-timing-function: ease-in-out;
+}
+
+.notice .button-link {
+	color: #0073aa;
+}
+
+.notice .button-link:hover,
+.notice .button-link:active {
+	color: #00a0d2;
+}
+
+@media aural {
+	.wrap .notice p:before,
+	.button.installing:before,
+	.button.installed:before,
+	.update-message p:before {
+		speak: none;
+	}
+}
+
 
 /* @todo: this does not need its own section anymore */
 /*------------------------------------------------------------------------------
```
