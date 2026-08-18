# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5452_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5452_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 70-110 of the vulnerable file.

			return true;
		}

		$path = $request->getPath();
		$node = $this->server->tree->getNodeForPath($path);

		if (!($node instanceof Card)) {
			return true;
		}

		$this->server->transactionType = 'carddav-image-export';

		// Checking ACL, if available.
		if ($aclPlugin = $this->server->getPlugin('acl')) {
			/** @var \Sabre\DAVACL\Plugin $aclPlugin */
			$aclPlugin->checkPrivileges($path, '{DAV:}read');
		}

		if ($result = $this->getPhoto($node)) {
			$response->setHeader('Content-Type', $result['Content-Type']);
			$response->setStatus(200);

			$response->setBody($result['body']);

			// Returning false to break the event chain
			return false;
		}
		return true;
	}

	function getPhoto(Card $node) {
		// TODO: this is kind of expensive - load carddav data from database and parse it
		//       we might want to build up a cache one day
		try {
			$vObject = $this->readCard($node->get());
			if (!$vObject->PHOTO) {
				return false;
			}

			$photo = $vObject->PHOTO;
			$type = $this->getType($photo);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -87,6 +87,7 @@
 
 		if ($result = $this->getPhoto($node)) {
 			$response->setHeader('Content-Type', $result['Content-Type']);
+			$response->setHeader('Content-Disposition', 'attachment');
 			$response->setStatus(200);
 
 			$response->setBody($result['body']);
@@ -121,6 +122,17 @@
 				}
 				$val = file_get_contents($val);
 			}
+
+			$allowedContentTypes = [
+				'image/png',
+				'image/jpeg',
+				'image/gif',
+			];
+
+			if(!in_array($type, $allowedContentTypes, true)) {
+				$type = 'application/octet-stream';
+			}
+
 			return [
 				'Content-Type' => $type,
 				'body' => $val
```
