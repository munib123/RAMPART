# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3354_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3354_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 4563-4603 of the vulnerable file.

						}
					} );
				};

				if ( 0 === processing() ) {
					submit();
				} else {
					submitWhenDoneProcessing = function () {
						if ( 0 === processing() ) {
							api.state.unbind( 'change', submitWhenDoneProcessing );
							submit();
						}
					};
					api.state.bind( 'change', submitWhenDoneProcessing );
				}

				return deferred.promise();
			}
		});

		// Refresh the nonces if the preview sends updated nonces over.
		api.previewer.bind( 'nonce', function( nonce ) {
			$.extend( this.nonce, nonce );
		});

		// Refresh the nonces if login sends updated nonces over.
		api.bind( 'nonce-refresh', function( nonce ) {
			$.extend( api.settings.nonce, nonce );
			$.extend( api.previewer.nonce, nonce );
			api.previewer.send( 'nonce-refresh', nonce );
		});

		// Create Settings
		$.each( api.settings.settings, function( id, data ) {
			var constructor = api.settingConstructor[ data.type ] || api.Setting,
				setting;

			setting = new constructor( id, data.value, {
				transport: data.transport,
				previewer: api.previewer,
				dirty: !! data.dirty
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4580,6 +4580,16 @@
 			}
 		});
 
+		// Ensure preview nonce is included with every customized request, to allow post data to be read.
+		$.ajaxPrefilter( function injectPreviewNonce( options ) {
+			if ( ! /wp_customize=on/.test( options.data ) ) {
+				return;
+			}
+			options.data += '&' + $.param({
+				customize_preview_nonce: api.settings.nonce.preview
+			});
+		});
+
 		// Refresh the nonces if the preview sends updated nonces over.
 		api.previewer.bind( 'nonce', function( nonce ) {
 			$.extend( this.nonce, nonce );
```
