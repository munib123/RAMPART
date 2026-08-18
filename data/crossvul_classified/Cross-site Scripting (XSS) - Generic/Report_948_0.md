# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 948_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `948_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1083-1123 of the vulnerable file.

				}

				unset($sAttrsForRemove);
			}

			if ($oElement->hasAttribute('href'))
			{
				$sHref = \trim($oElement->getAttribute('href'));
				if (!\preg_match('/^(http[s]?|ftp|skype|mailto):/i', $sHref) && '//' !== \substr($sHref, 0, 2))
				{
					$oElement->setAttribute('data-x-broken-href', $sHref);
					$oElement->setAttribute('href', 'javascript:false');
				}

				if ('a' === $sTagNameLower)
				{
					$oElement->setAttribute('rel', 'external nofollow noopener noreferrer');
				}
			}

			if (\in_array($sTagNameLower, array('a', 'form', 'area')))
			{
				$oElement->setAttribute('target', '_blank');
			}

			if (\in_array($sTagNameLower, array('a', 'form', 'area', 'input', 'button', 'textarea')))
			{
				$oElement->setAttribute('tabindex', '-1');
			}

			if ($bTryToDetectHiddenImages && 'img' === $sTagNameLower)
			{
				$sAlt = $oElement->hasAttribute('alt')
					? \trim($oElement->getAttribute('alt')) : '';

				if ($oElement->hasAttribute('src') && '' === $sAlt)
				{
					$aH = array(
						'email.microsoftemail.com/open',
						'github.com/notifications/beacon/',
						'mandrillapp.com/track/open',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1100,6 +1100,13 @@
 				}
 			}
 
+			$sLinkHref = \trim($oElement->getAttribute('xlink:href'));
+			if ($sLinkHref && !\preg_match('/^(http[s]?):/i', $sLinkHref) && '//' !== \substr($sLinkHref, 0, 2))
+			{
+				$oElement->setAttribute('data-x-blocked-xlink-href', $sLinkHref);
+				$oElement->removeAttribute('xlink:href');
+			}
+			
 			if (\in_array($sTagNameLower, array('a', 'form', 'area')))
 			{
 				$oElement->setAttribute('target', '_blank');
```
