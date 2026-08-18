# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 948_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `948_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 481-521 of the vulnerable file.


	/**
	 * @return string
	 */
	public function ServiceRaw()
	{
		$sResult = '';
		$sRawError = '';
		$sAction = empty($this->aPaths[2]) ? '' : $this->aPaths[2];
		$oException = null;

		try
		{
			$sRawError = 'Invalid action';
			if (0 !== \strlen($sAction))
			{
				$sMethodName = 'Raw'.$sAction;
				if (\method_exists($this->oActions, $sMethodName))
				{
					@\header('X-Raw-Action: '.$sMethodName, true);

					$sRawError = '';
					$this->oActions->SetActionParams(array(
						'RawKey' => empty($this->aPaths[3]) ? '' : $this->aPaths[3],
						'Params' => $this->aPaths
					), $sMethodName);

					if (!\call_user_func(array($this->oActions, $sMethodName)))
					{
						$sRawError = 'False result';
					}
					else
					{
						$sRawError = '';
					}
				}
				else
				{
					$sRawError = 'Unknown action "'.$sAction.'"';
				}
			}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -498,6 +498,7 @@
 				if (\method_exists($this->oActions, $sMethodName))
 				{
 					@\header('X-Raw-Action: '.$sMethodName, true);
+					@\header('Content-Security-Policy: default-src \'self\'; script-src \'none\'; style-src \'none\'; frame-src \'none\'; child-src \'none\'', true);
 
 					$sRawError = '';
 					$this->oActions->SetActionParams(array(
```
