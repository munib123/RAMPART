# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3352_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3352_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 311-352 of the vulnerable file.

				wpQueueError(pluploadL10n.io_error);
			break;
		case plupload.HTTP_ERROR:
			wpQueueError(pluploadL10n.http_error);
			break;
		case plupload.INIT_ERROR:
			jQuery('.media-upload-form').addClass('html-uploader');
			break;
		case plupload.SECURITY_ERROR:
			wpQueueError(pluploadL10n.security_error);
			break;
/*		case plupload.UPLOAD_ERROR.UPLOAD_STOPPED:
		case plupload.UPLOAD_ERROR.FILE_CANCELLED:
			jQuery('#media-item-' + fileObj.id).remove();
			break;*/
		default:
			wpFileError(fileObj, pluploadL10n.default_error);
	}
}

function uploadSizeError( up, file, over100mb ) {
	var message;

	if ( over100mb )
		message = pluploadL10n.big_upload_queued.replace('%s', file.name) + ' ' + pluploadL10n.big_upload_failed.replace('%1$s', '<a class="uploader-html" href="#">').replace('%2$s', '</a>');
	else
		message = pluploadL10n.file_exceeds_size_limit.replace('%s', file.name);

	jQuery('#media-items').append('<div id="media-item-' + file.id + '" class="media-item error"><p>' + message + '</p></div>');
	up.removeFile(file);
}

function wpFileExtensionError( up, file, message ) {
	jQuery('#media-items').append('<div id="media-item-' + file.id + '" class="media-item error"><p>' + message + '</p></div>');
	up.removeFile(file);
}

jQuery(document).ready(function($){
	$('.media-upload-form').bind('click.uploader', function(e) {
		var target = $(e.target), tr, c;

		if ( target.is('input[type="radio"]') ) { // remember the last used image size and alignment
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -328,15 +328,24 @@
 	}
 }
 
-function uploadSizeError( up, file, over100mb ) {
-	var message;
-
-	if ( over100mb )
-		message = pluploadL10n.big_upload_queued.replace('%s', file.name) + ' ' + pluploadL10n.big_upload_failed.replace('%1$s', '<a class="uploader-html" href="#">').replace('%2$s', '</a>');
-	else
-		message = pluploadL10n.file_exceeds_size_limit.replace('%s', file.name);
-
-	jQuery('#media-items').append('<div id="media-item-' + file.id + '" class="media-item error"><p>' + message + '</p></div>');
+function uploadSizeError( up, file ) {
+	var message, errorDiv;
+
+	message = pluploadL10n.file_exceeds_size_limit.replace('%s', file.name);
+
+	// Construct the error div.
+	errorDiv = jQuery( '<div />' )
+		.attr( {
+			'id':    'media-item-' + file.id,
+			'class': 'media-item error'
+		} )
+		.append(
+			jQuery( '<p />' )
+				.text( message )
+		);
+
+	// Append the error.
+	jQuery('#media-items').append( errorDiv );
 	up.removeFile(file);
 }
 
```
