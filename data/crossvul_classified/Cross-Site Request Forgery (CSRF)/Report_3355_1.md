# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in javascript
**Pair ID:** 3355_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3355_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```javascript
Lines 77-117 of the vulnerable file.

	 * @type {bool}
	 */
	wp.updates.shouldRequestFilesystemCredentials = false;

	/**
	 * Filesystem credentials to be packaged along with the request.
	 *
	 * @since 4.2.0
	 * @since 4.6.0 Added `available` property to indicate whether credentials have been provided.
	 *
	 * @type {object} filesystemCredentials                    Holds filesystem credentials.
	 * @type {object} filesystemCredentials.ftp                Holds FTP credentials.
	 * @type {string} filesystemCredentials.ftp.host           FTP host. Default empty string.
	 * @type {string} filesystemCredentials.ftp.username       FTP user name. Default empty string.
	 * @type {string} filesystemCredentials.ftp.password       FTP password. Default empty string.
	 * @type {string} filesystemCredentials.ftp.connectionType Type of FTP connection. 'ssh', 'ftp', or 'ftps'.
	 *                                                         Default empty string.
	 * @type {object} filesystemCredentials.ssh                Holds SSH credentials.
	 * @type {string} filesystemCredentials.ssh.publicKey      The public key. Default empty string.
	 * @type {string} filesystemCredentials.ssh.privateKey     The private key. Default empty string.
	 * @type {bool}   filesystemCredentials.available          Whether filesystem credentials have been provided.
	 *                                                         Default 'false'.
	 */
	wp.updates.filesystemCredentials = {
		ftp:       {
			host:           '',
			username:       '',
			password:       '',
			connectionType: ''
		},
		ssh:       {
			publicKey:  '',
			privateKey: ''
		},
		available: false
	};

	/**
	 * Whether we're waiting for an Ajax request to complete.
	 *
	 * @since 4.2.0
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -94,6 +94,7 @@
 	 * @type {object} filesystemCredentials.ssh                Holds SSH credentials.
 	 * @type {string} filesystemCredentials.ssh.publicKey      The public key. Default empty string.
 	 * @type {string} filesystemCredentials.ssh.privateKey     The private key. Default empty string.
+	 * @type {string} filesystemCredentials.fsNonce            Filesystem credentials form nonce.
 	 * @type {bool}   filesystemCredentials.available          Whether filesystem credentials have been provided.
 	 *                                                         Default 'false'.
 	 */
@@ -108,6 +109,7 @@
 			publicKey:  '',
 			privateKey: ''
 		},
+		fsNonce: '',
 		available: false
 	};
 
@@ -225,6 +227,7 @@
 		options.data = _.extend( data, {
 			action:          action,
 			_ajax_nonce:     wp.updates.ajaxNonce,
+			_fs_nonce:       wp.updates.filesystemCredentials.fsNonce,
 			username:        wp.updates.filesystemCredentials.ftp.username,
 			password:        wp.updates.filesystemCredentials.ftp.password,
 			hostname:        wp.updates.filesystemCredentials.ftp.hostname,
@@ -1706,6 +1709,7 @@
 			wp.updates.filesystemCredentials.ftp.connectionType = $( 'input[name="connection_type"]:checked' ).val();
 			wp.updates.filesystemCredentials.ssh.publicKey      = $( '#public_key' ).val();
 			wp.updates.filesystemCredentials.ssh.privateKey     = $( '#private_key' ).val();
+			wp.updates.filesystemCredentials.fsNonce            = $( '#_fs_nonce' ).val();
 			wp.updates.filesystemCredentials.available          = true;
 
 			// Unlock and invoke the queue.
```
