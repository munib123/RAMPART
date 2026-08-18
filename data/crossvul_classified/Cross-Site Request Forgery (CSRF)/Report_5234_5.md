# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in css
**Pair ID:** 5234_5
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** css
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5234_5`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```css
Lines 1027-1067 of the vulnerable file.

.request-filesystem-credentials-dialog label[for="ftp"] {
	margin-left: 10px;
}

.request-filesystem-credentials-dialog #auth-keys-desc {
	margin-bottom: 0;
}

#request-filesystem-credentials-dialog .button:not(:last-child) {
	margin-left: 10px;
}

#request-filesystem-credentials-form .cancel-button {
	display: none;
}

#request-filesystem-credentials-dialog .cancel-button {
	display: inline;
}


/* =Media Queries
-------------------------------------------------------------- */

@media screen and ( max-width: 782px ) {
	/* Input Elements */
	textarea {
		-webkit-appearance: none;
	}

	input[type="text"],
	input[type="email"],
	input[type="search"],
	input[type="password"],
	input[type="number"] {
		-webkit-appearance: none;
		padding: 6px 10px;
	}

	input[type="number"] {
		height: 40px;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1044,6 +1044,43 @@
 	display: inline;
 }
 
+.request-filesystem-credentials-dialog .ftp-username,
+.request-filesystem-credentials-dialog .ftp-password {
+	float: none;
+	width: auto;
+}
+
+.request-filesystem-credentials-dialog .ftp-username {
+	margin-bottom: 1em;
+}
+
+.request-filesystem-credentials-dialog .ftp-password {
+	margin: 0;
+}
+
+.request-filesystem-credentials-dialog .ftp-password em {
+	color: #888;
+}
+
+.request-filesystem-credentials-dialog label {
+	display: block;
+	line-height: 1.5;
+	margin-bottom: 1em;
+}
+
+.request-filesystem-credentials-form legend {
+	padding-bottom: 0;
+}
+
+.request-filesystem-credentials-form #ssh-keys legend {
+	font-size: 1.3em;
+}
+
+.request-filesystem-credentials-form .notice {
+	margin: 0 0 20px 0;
+	clear: both;
+}
+
 
 /* =Media Queries
 -------------------------------------------------------------- */
```
